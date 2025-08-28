# GcmCrypt-Python

Python port of [GcmCrypt (.NET)](https://github.com/lellis1936/GcmCrypt).  
Implements the same AES-GCM file format, header structure, and chunking rules as documented in the .NET repo.

Language translation by ChatGPT-5

## Features
- Encrypt/decrypt files with AES-256 GCM
- Intended file-format compatibility with the .NET version (header, chunking, 16-byte tags)
- Cross-platform (Windows, Linux, macOS)
- Console messages aligned with .NET where practical (e.g., clearer GCM auth-tag failures)

## Requirements
- **Python 3.6+**  
  *Note: Python 3.6 is end-of-life; newer Python versions are recommended for security and support.*
- `cryptography` (preferred)
```
pip install cryptography
```
- Optional fallback: `pycryptodome`

## Usage
```
# Encrypt
python gcmcrypt.py -e password input.txt output.gcm

# Decrypt
python gcmcrypt.py -d password input.gcm output.txt
```

## Interop
- The goal is for files encrypted with this script to decrypt with the .NET `GcmCrypt`, and vice versa.
- Follow the .NET repo’s “Encrypted File Format” and “AES GCM Mode Technical Notes” for parity.

## Notes
If a decryption fails due to an authentication error and the underlying library error is empty, the script should print:
```
Decryption failed: likely wrong password or corrupted file
```

## License
MIT — same as the .NET project.
