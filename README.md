# GcmCrypt-Python

Cross-platform Python port of [GcmCrypt (.NET)](https://github.com/lellis1936/GcmCrypt).
It implements the same AES-256-GCM file format, password derivation, compression
framing, chunking, authentication, and command-line behavior as GcmCrypt v1.5.0.

## Compatibility

- Writes encrypted file format 1.5 using PBKDF2-HMAC-SHA256.
- Reads encrypted file formats 1.1, 1.2, 1.3, and 1.5.
- Interoperates in both directions with the .NET Framework 4.8 and .NET 8 builds.
- Uses the same default PBKDF2 iteration count as the C# implementation: 600,000.
- Stores and authenticates the PBKDF2 iteration count in the v1.5 header.
- Authenticates the original plaintext length, detecting removal of complete
  trailing chunks.
- Decrypts to `output.PARTIAL` and only publishes `output` after complete
  authentication and length validation.

## Requirements

- Python 3.6 or newer. A currently supported Python release is recommended.
- [`cryptography`](https://pypi.org/project/cryptography/) (preferred AES-GCM
  backend), or `pycryptodome` as an AES-GCM fallback.

    pip install -r requirements.txt

No external KDF dependency is required; PBKDF2-HMAC-SHA256 is provided by Python's
standard library.

## Usage

    # Encrypt
    python gcmcrypt.py -e password input.txt output.gcm

    # Encrypt with a custom PBKDF2 iteration count
    python gcmcrypt.py -e -iter 750000 password input.txt output.gcm

    # Encrypt with gzip compression
    python gcmcrypt.py -e -compress password input.txt output.gcm

    # Decrypt
    python gcmcrypt.py -d password input.gcm output.txt

Use `-f` to overwrite an existing output without prompting.

## Tests

Run the Python regression suite:

    python -m unittest discover -s tests -v

Run bidirectional interoperability checks against a built C# executable:

    .\smoke-test.ps1 -CSharpExe C:\path\to\GcmCrypt.exe

## License

MIT, matching the .NET project.
