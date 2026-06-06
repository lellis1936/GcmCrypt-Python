# GcmCrypt-Python

Cross-platform Python port of [GcmCrypt (.NET)](https://github.com/lellis1936/GcmCrypt).
It implements the same AES-256-GCM file format, password derivation, compression
framing, chunking, authentication, and command-line behavior as GcmCrypt v1.4.1.

## Compatibility

- Writes encrypted file format 1.3.
- Reads encrypted file formats 1.1, 1.2, and 1.3.
- Interoperates in both directions with the .NET Framework 4.8 and .NET 8 builds.
- Authenticates the original plaintext length, detecting removal of complete
  trailing chunks.
- Decrypts to `output.PARTIAL` and only publishes `output` after complete
  authentication and length validation.

## Requirements

- Python 3.6 or newer. A currently supported Python release is recommended.
- [`cryptography`](https://pypi.org/project/cryptography/) (preferred), or
  `pycryptodome` as a fallback.

```console
pip install cryptography
```

## Usage

```console
# Encrypt
python gcmcrypt.py -e password input.txt output.gcm

# Encrypt with gzip compression
python gcmcrypt.py -e -compress password input.txt output.gcm

# Decrypt
python gcmcrypt.py -d password input.gcm output.txt
```

Use `-f` to overwrite an existing output without prompting.

## Tests

Run the Python regression suite:

```console
python -m unittest discover -s tests -v
```

Run bidirectional interoperability checks against a built C# executable:

```powershell
.\smoke-test.ps1 -CSharpExe C:\path\to\GcmCrypt.exe
```

## License

MIT, matching the .NET project.
