import contextlib
import io
import os
import struct
import tempfile
import unittest

import gcmcrypt


class GcmCryptTests(unittest.TestCase):
    PASSWORD = "passw\u00f6rd-\u6f22\u5b57"

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)

    def path(self, name):
        return os.path.join(self.tempdir.name, name)

    def capture(self, function, *args, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            function(*args, **kwargs)
        return output.getvalue()

    def test_cli_parser_matches_csharp_switch_behavior(self):
        self.assertEqual(
            (
                True,
                True,
                True,
                gcmcrypt.DEFAULT_PBKDF2_ITERATIONS,
                False,
                "password",
                "input",
                "output",
            ),
            gcmcrypt._parse_args(
                ["-E", "-F", "-COMPRESS", "password", "input", "output"]
            ),
        )
        self.assertEqual(
            (
                False,
                False,
                False,
                gcmcrypt.DEFAULT_PBKDF2_ITERATIONS,
                False,
                "password",
                "input",
                "output",
            ),
            gcmcrypt._parse_args(["-D", "-unknown", "password", "input", "output"]),
        )
        self.assertEqual(
            (True, False, False, 750000, True, "password", "input", "output"),
            gcmcrypt._parse_args(
                ["-e", "-iter", "750000", "password", "input", "output"]
            ),
        )

    def test_cli_parser_requires_one_mode_and_exactly_three_parameters(self):
        invalid_arguments = (
            [],
            ["-e", "-d", "password", "input", "output"],
            ["-e", "password", "input"],
            ["-e", "password", "input", "output", "extra"],
            ["--encrypt", "password", "input", "output"],
            ["-e", "-iter", "99999", "password", "input", "output"],
            ["-e", "-iter", "10000001", "password", "input", "output"],
            ["-e", "-iter", "not-a-number", "password", "input", "output"],
            ["-e", "-iter", "password", "input", "output"],
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                self.assertIsNone(gcmcrypt._parse_args(arguments))

    def round_trip(self, data, compressed=False):
        source = self.path("source.bin")
        encrypted = self.path("encrypted.gcm")
        decrypted = self.path("decrypted.bin")
        with open(source, "wb") as stream:
            stream.write(data)

        self.capture(
            gcmcrypt.encrypt,
            self.PASSWORD,
            source,
            encrypted,
            force=True,
            do_compress=compressed,
        )
        self.capture(
            gcmcrypt.decrypt,
            self.PASSWORD,
            encrypted,
            decrypted,
            force=True,
        )

        with open(decrypted, "rb") as stream:
            self.assertEqual(data, stream.read())
        self.assertFalse(os.path.exists(decrypted + ".PARTIAL"))
        return encrypted

    def write_legacy_file(self, filename, data, minor_version):
        salt = os.urandom(gcmcrypt.SALT_LEN)
        iterations = 10000 if minor_version == 1 else 100000
        master_key = gcmcrypt._pbkdf2_sha256(
            self.PASSWORD.encode("utf-8"), salt, iterations, gcmcrypt.KEY_LEN
        )
        file_key = os.urandom(gcmcrypt.KEY_LEN)
        encrypted_file_key, file_key_tag = gcmcrypt._aesgcm_encrypt(
            master_key, gcmcrypt.FEK_NONCE, file_key, aad=None
        )
        header = (
            gcmcrypt.MAGIC
            + bytes([gcmcrypt.VER_MAJOR, minor_version])
            + salt
            + encrypted_file_key
            + file_key_tag
            + b"\x00"
            + struct.pack(">I", gcmcrypt.DEFAULT_CHUNK)
        )
        if minor_version == 3:
            header += struct.pack(">q", len(data))
        _, header_tag = gcmcrypt._aesgcm_encrypt(
            master_key, gcmcrypt.HEADER_NONCE, b"", aad=header
        )

        with open(filename, "wb") as stream:
            stream.write(header)
            stream.write(header_tag)
            nonce = bytearray(gcmcrypt.NONCE_LEN)
            for offset in range(0, len(data), gcmcrypt.DEFAULT_CHUNK):
                gcmcrypt._inc_nonce(nonce)
                ciphertext, tag = gcmcrypt._aesgcm_encrypt(
                    file_key,
                    bytes(nonce),
                    data[offset:offset + gcmcrypt.DEFAULT_CHUNK],
                    aad=None,
                )
                stream.write(ciphertext)
                stream.write(tag)

    def test_round_trip_plain_sizes(self):
        for size in (0, 1, 65535, 65536, 65537, 131072):
            with self.subTest(size=size):
                self.round_trip(bytes((index % 251 for index in range(size))))

    def test_round_trip_compressed(self):
        self.round_trip((b"GcmCrypt compression test\n" * 10000), compressed=True)

    def test_writes_v1_5_pbkdf2_iterations(self):
        data = b"authenticated length"
        encrypted = self.round_trip(data)
        with open(encrypted, "rb") as stream:
            header = stream.read(gcmcrypt.V1_5_HEADER_LEN)

        self.assertEqual(b"GCM\x01\x05", header[:5])
        self.assertEqual(len(data), struct.unpack(">q", header[74:82])[0])
        self.assertEqual(
            gcmcrypt.DEFAULT_PBKDF2_ITERATIONS,
            struct.unpack(">I", header[82:86])[0],
        )

    def test_custom_iteration_count_round_trips(self):
        source = self.path("source.bin")
        encrypted = self.path("encrypted.gcm")
        decrypted = self.path("decrypted.bin")
        with open(source, "wb") as stream:
            stream.write(b"custom iterations")

        self.capture(
            gcmcrypt.encrypt,
            self.PASSWORD,
            source,
            encrypted,
            force=True,
            iterations=750000,
        )
        with open(encrypted, "rb") as stream:
            header = stream.read(gcmcrypt.V1_5_HEADER_LEN)
        self.assertEqual(750000, struct.unpack(">I", header[82:86])[0])

        self.capture(
            gcmcrypt.decrypt,
            self.PASSWORD,
            encrypted,
            decrypted,
            force=True,
        )
        with open(decrypted, "rb") as stream:
            self.assertEqual(b"custom iterations", stream.read())

    def test_reads_legacy_v1_1_through_v1_3(self):
        data = b"legacy format data" * 5000
        for minor_version in (1, 2, 3):
            with self.subTest(minor_version=minor_version):
                encrypted = self.path("legacy-{0}.gcm".format(minor_version))
                output = self.path("legacy-{0}.bin".format(minor_version))
                self.write_legacy_file(encrypted, data, minor_version)

                self.capture(
                    gcmcrypt.decrypt,
                    self.PASSWORD,
                    encrypted,
                    output,
                    force=True,
                )

                with open(output, "rb") as stream:
                    self.assertEqual(data, stream.read())

    def test_rejects_non_gcmcrypt_signature_before_checking_version(self):
        source = self.path("not-gcmcrypt.bin")
        output = self.path("output.bin")
        with open(source, "wb") as stream:
            stream.write(b"NOT\xff\xff")

        messages = self.capture(
            gcmcrypt.decrypt, self.PASSWORD, source, output, force=True
        )

        self.assertIn("Input file is not a GcmCrypt file", messages)
        self.assertNotIn("Unsupported input file version", messages)
        self.assertFalse(os.path.exists(output))

    def test_rejects_unsupported_version_after_valid_signature(self):
        source = self.path("unsupported-version.gcm")
        output = self.path("output.bin")
        with open(source, "wb") as stream:
            stream.write(gcmcrypt.MAGIC + b"\xff\xff")

        messages = self.capture(
            gcmcrypt.decrypt, self.PASSWORD, source, output, force=True
        )

        self.assertIn("Unsupported input file version", messages)
        self.assertFalse(os.path.exists(output))

    def test_invalid_pbkdf2_iterations_are_rejected_before_derivation(self):
        source = self.path("source.bin")
        encrypted = self.path("encrypted.gcm")
        invalid = self.path("invalid.gcm")
        output = self.path("output.bin")
        with open(source, "wb") as stream:
            stream.write(b"parameter validation")
        self.capture(
            gcmcrypt.encrypt, self.PASSWORD, source, encrypted, force=True
        )
        with open(encrypted, "rb") as stream:
            encrypted_data = bytearray(stream.read())
        encrypted_data[82:86] = struct.pack(">I", gcmcrypt.MIN_PBKDF2_ITERATIONS - 1)
        with open(invalid, "wb") as stream:
            stream.write(encrypted_data)

        messages = self.capture(
            gcmcrypt.decrypt, self.PASSWORD, invalid, output, force=True
        )

        self.assertIn("invalid PBKDF2 iteration count", messages)
        self.assertFalse(os.path.exists(output))
        self.assertFalse(os.path.exists(output + ".PARTIAL"))

    def test_complete_trailing_chunk_removal_is_detected_and_retained(self):
        source = self.path("source.bin")
        encrypted = self.path("encrypted.gcm")
        truncated = self.path("truncated.gcm")
        output = self.path("output.bin")
        data = bytes((index % 251 for index in range(3 * gcmcrypt.DEFAULT_CHUNK)))
        with open(source, "wb") as stream:
            stream.write(data)
        self.capture(
            gcmcrypt.encrypt, self.PASSWORD, source, encrypted, force=True
        )
        with open(encrypted, "rb") as stream:
            encrypted_data = stream.read()
        with open(truncated, "wb") as stream:
            stream.write(encrypted_data[:-(gcmcrypt.DEFAULT_CHUNK + gcmcrypt.TAG_LEN)])

        messages = self.capture(
            gcmcrypt.decrypt, self.PASSWORD, truncated, output, force=True
        )

        self.assertIn("Decrypted file length mismatch", messages)
        self.assertFalse(os.path.exists(output))
        self.assertTrue(os.path.exists(output + ".PARTIAL"))
        self.assertEqual(2 * gcmcrypt.DEFAULT_CHUNK, os.path.getsize(output + ".PARTIAL"))

    def test_failed_decryption_preserves_existing_output(self):
        source = self.path("source.bin")
        encrypted = self.path("encrypted.gcm")
        output = self.path("output.bin")
        with open(source, "wb") as stream:
            stream.write(b"secret")
        with open(output, "wb") as stream:
            stream.write(b"existing output")
        self.capture(
            gcmcrypt.encrypt, self.PASSWORD, source, encrypted, force=True
        )

        self.capture(
            gcmcrypt.decrypt, "wrong password", encrypted, output, force=True
        )

        with open(output, "rb") as stream:
            self.assertEqual(b"existing output", stream.read())
        self.assertFalse(os.path.exists(output + ".PARTIAL"))

    def test_success_replaces_existing_output_and_stale_partial(self):
        source = self.path("source.bin")
        encrypted = self.path("encrypted.gcm")
        output = self.path("output.bin")
        data = b"replacement output"
        with open(source, "wb") as stream:
            stream.write(data)
        with open(output, "wb") as stream:
            stream.write(b"existing output")
        with open(output + ".PARTIAL", "wb") as stream:
            stream.write(b"stale partial output")
        self.capture(
            gcmcrypt.encrypt, self.PASSWORD, source, encrypted, force=True
        )

        self.capture(
            gcmcrypt.decrypt, self.PASSWORD, encrypted, output, force=True
        )

        with open(output, "rb") as stream:
            self.assertEqual(data, stream.read())
        self.assertFalse(os.path.exists(output + ".PARTIAL"))


if __name__ == "__main__":
    unittest.main()
