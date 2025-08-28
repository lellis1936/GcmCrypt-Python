#!/usr/bin/env python3
# gcmcrypt.py — GcmCrypt-compatible with identical console messages/timings.

import argparse, os, sys, struct, zlib, getpass, hashlib, time

# AES-GCM backend
_BACKEND = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM_Crypto
    _BACKEND = "cryptography"
except Exception:
    try:
        from Crypto.Cipher import AES as _AES_PYCD
        _BACKEND = "pycryptodome"
    except Exception:
        _BACKEND = None

# Constants per Program.cs
MAGIC = b"GCM"
VER_MAJOR = 1
VER_MINOR = 2  # write 1.2; read accepts 1.1/1.2
NONCE_LEN = 12
KEY_LEN   = 32
TAG_LEN   = 16
SALT_LEN  = 16
V1_HEADER_LEN = 74
HEADER_NONCE = bytes([0xFF])*NONCE_LEN
FEK_NONCE    = bytes([0x00])*NONCE_LEN
DEFAULT_CHUNK = 64*1024

def _pbkdf2_sha256(password, salt, iterations, dklen=32):
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)

def _inc_nonce(nonce):
    for i in range(len(nonce)-1, -1, -1):
        nonce[i] = (nonce[i] + 1) & 0xFF
        if nonce[i] != 0:
            return

def _aesgcm_encrypt(key, nonce, plaintext, aad):
    if _BACKEND == "cryptography":
        a = _AESGCM_Crypto(key)
        data = a.encrypt(nonce, plaintext, aad)  # returns ct||tag
        return data[:-16], data[-16:]
    elif _BACKEND == "pycryptodome":
        cipher = _AES_PYCD.new(key, _AES_PYCD.MODE_GCM, nonce=nonce, mac_len=16)
        if aad:
            cipher.update(aad)
        c = cipher.encrypt(plaintext)
        tag = cipher.digest()
        return c, tag
    else:
        raise RuntimeError("No AES-GCM backend available. Install 'cryptography' or 'pycryptodome'.")

def _aesgcm_decrypt(key, nonce, ciphertext, tag, aad):
    if _BACKEND == "cryptography":
        a = _AESGCM_Crypto(key)
        return a.decrypt(nonce, ciphertext + tag, aad)
    elif _BACKEND == "pycryptodome":
        cipher = _AES_PYCD.new(key, _AES_PYCD.MODE_GCM, nonce=nonce, mac_len=16)
        if aad:
            cipher.update(aad)
        pt = cipher.decrypt(ciphertext)
        cipher.verify(tag)  # raises on failure
        return pt
    else:
        raise RuntimeError("No AES-GCM backend available. Install 'cryptography' or 'pycryptodome'.")

def print_usage():
    version = f"{VER_MAJOR}.{VER_MINOR}"
    print(f"GcmCrypt v{version}")
    print("Usage is : ")
    print("\tpython GcmCrypt.py -e|-d [-f] [-compress] password infile outfile. ")
    print()
    print("Examples:")
    print("\tpython GcmCrypt.py -e -compress mypass myinputfile myencryptedoutputfile")
    print("\tpython GcmCrypt.py -d mypass myencryptedinputfile mydecryptedoutputfile")
    print()
    print("\n-compress option only needed for encryption")
    print("\n-f option will silently overwrite the output file if it exists")
    print()

def encrypt(password, infile, outfile, force=False, do_compress=False, chunk_size=DEFAULT_CHUNK):
    if not _BACKEND:
        raise SystemExit("Encryption failed: AES-GCM backend not available")
    if (not force) and os.path.exists(outfile):
        raise SystemExit("Encryption failed: Output file exists (use -f)")

    try:
        # KDF timing
        salt = os.urandom(SALT_LEN)
        iterations = 100000  # v1.2
        sw = time.time()
        mk = _pbkdf2_sha256(password.encode("utf-8"), salt, iterations, KEY_LEN)
        print(f"Key derivation took {int((time.time()-sw)*1000)} ms")

        # Prepare input
        with open(infile, "rb") as f:
            data = f.read()
        if do_compress:
            data = zlib.compress(data)

        # FEK wrap
        fek = os.urandom(KEY_LEN)
        fek_ct, fek_tag = _aesgcm_encrypt(mk, FEK_NONCE, fek, aad=None)

        # Header
        header = bytearray()
        header += MAGIC
        header += bytes([VER_MAJOR])
        header += bytes([VER_MINOR])
        header += salt
        header += fek_ct
        header += fek_tag
        header += bytes([1 if do_compress else 0])
        header += struct.pack(">I", chunk_size)
        assert len(header) == V1_HEADER_LEN
        _, header_tag = _aesgcm_encrypt(mk, HEADER_NONCE, b"", aad=bytes(header))

        # Encrypt data
        sw = time.time()
        out = bytearray()
        out += header
        out += header_tag
        nonce = bytearray(NONCE_LEN)
        offset = 0
        total = len(data)
        while offset < total:
            _inc_nonce(nonce)
            chunk = data[offset: offset+chunk_size]
            ct, tag = _aesgcm_encrypt(fek, bytes(nonce), chunk, aad=None)
            out += ct
            out += tag
            offset += len(chunk)

        with open(outfile, "wb") as f:
            f.write(out)

        print("File encrypted. AES GCM encryption took {0} ms".format(int((time.time()-sw)*1000)))
    except Exception as ex:
        print(f"Encryption failed: {str(ex)}")

def decrypt(password, infile, outfile, force=False):
    if not _BACKEND:
        raise SystemExit("Decryption failed: AES-GCM backend not available")
    if (not force) and os.path.exists(outfile):
        raise SystemExit("Decryption failed: Output file exists (use -f)")

    try:
        with open(infile, "rb") as f:
            blob = f.read()

        # Parse header
        if len(blob) < (V1_HEADER_LEN + TAG_LEN):
            print("Unsupported input file version")
            return
        p = 0
        magic = blob[p:p+3]; p+=3
        if magic != MAGIC:
            print("Unsupported input file version")
            return
        verMajor = blob[p]; p+=1
        verMinor = blob[p]; p+=1
        if verMajor != 1 or verMinor not in (1,2):
            print("Unsupported input file version")
            return
        salt = blob[p:p+SALT_LEN]; p+=SALT_LEN
        fek_ct = blob[p:p+KEY_LEN]; p+=KEY_LEN
        fek_tag = blob[p:p+TAG_LEN]; p+=TAG_LEN
        compressed_flag = blob[p]; p+=1
        chunk_size = struct.unpack(">I", blob[p:p+4])[0]; p+=4
        header = blob[:V1_HEADER_LEN]
        header_tag = blob[p:p+TAG_LEN]; p+=TAG_LEN

        # KDF (v1.1 vs v1.2)
        iterations = 10000 if verMinor == 1 else 100000
        sw = time.time()
        mk = _pbkdf2_sha256(password.encode("utf-8"), salt, iterations, KEY_LEN)
        print(f"Key derivation took {int((time.time()-sw)*1000)} ms")

        # Verify header tag
        _ = _aesgcm_decrypt(mk, HEADER_NONCE, b"", header_tag, aad=header)

        # Unwrap FEK
        fek = _aesgcm_decrypt(mk, FEK_NONCE, fek_ct, fek_tag, aad=None)

        # Decrypt chunks
        sw = time.time()
        nonce = bytearray(NONCE_LEN)
        out = bytearray()
        i = p
        n = len(blob)
        while i < n:
            _inc_nonce(nonce)
            remaining = n - i
            if remaining < TAG_LEN:
                raise ValueError("Truncated chunk/tag.")
            ct_len = chunk_size if remaining >= (chunk_size + TAG_LEN) else (remaining - TAG_LEN)
            ct = blob[i:i+ct_len]; i += ct_len
            tag = blob[i:i+TAG_LEN]; i += TAG_LEN
            pt = _aesgcm_decrypt(fek, bytes(nonce), ct, tag, aad=None)
            out += pt

        if compressed_flag == 1:
            out = zlib.decompress(out)

        with open(outfile, "wb") as f:
            f.write(out)

        print("File decrypted successfully. AES GCM decryption took {0} ms.".format(int((time.time()-sw)*1000)))
    except Exception as ex:
        msg = str(ex).strip()
        if not msg:
            msg = "likely wrong password or corrupted file"
        print(f"Decryption failed: {msg}")
    finally:
        print()

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-e", "--encrypt", action="store_true")
    parser.add_argument("-d", "--decrypt", action="store_true")
    parser.add_argument("-f", action="store_true")
    parser.add_argument("-compress", action="store_true")
    parser.add_argument("password", nargs="?")
    parser.add_argument("infile", nargs="?")
    parser.add_argument("outfile", nargs="?")
    args, unknown = parser.parse_known_args()

    # Match .NET usage behavior if args are insufficient
    if not (args.encrypt ^ args.decrypt) or args.password is None or args.infile is None or args.outfile is None:
        print_usage()
        return

    if args.encrypt:
        encrypt(args.password, args.infile, args.outfile, force=args.f, do_compress=args.compress)
    else:
        decrypt(args.password, args.infile, args.outfile, force=args.f)

if __name__ == "__main__":
    main()
