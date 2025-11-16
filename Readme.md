
# Parallel Text File Encryptor / Decryptor

Small Python utility to encrypt/decrypt text files in parallel using `cryptography.Fernet`. Encrypted outputs are Base64-encoded text files so encrypted data remains printable `.txt`.

## Features
- Parallel processing (ProcessPoolExecutor)
- Single persistent symmetric key stored in `secret.key`
- Encrypted output is Base64 text (e.g. `file_encrypted.txt`)
- Simple CLI: enter file paths separated by spaces

## Requirements
- Python 3.8+
- `cryptography` package

Install:
```bash
pip install cryptography
````

## Files

* `parallel_text_crypto.py` — main script
* `secret.key` — generated automatically on first run (do not delete if you need to decrypt)

## Usage

Run the script:

```bash
python main.py


1. Choose:

   * `1` → Encrypt
   * `2` → Decrypt
2. Enter file paths separated by spaces, for example:

```
file1.txt notes.txt somefile.txt
```

> Note: the current implementation uses `str.split()` and does not support file paths containing spaces.

## Output naming

* Encryption: `file.txt` → `file_encrypted.txt`
* Decryption: `file_encrypted.txt` → `file_decrypted.txt`


## Important security notes

* `secret.key` holds the symmetric key needed to decrypt files. Backup this file. If it is lost, any files encrypted with it cannot be decrypted.
* `Fernet` provides authenticated encryption (AES-128 + HMAC) via the `cryptography` library.
* The script reads full files into memory. For very large files, consider a streaming approach.
* This implementation stores the same key for all files.

## Limitations & possible improvements

* Does not support file paths with spaces (CLI input uses whitespace split).
* Whole-file memory loading — convert to streaming for large files.
* No progress reporting — can add `tqdm`.
* No password-based key derivation (PBKDF2).
* No atomic write/replace — consider writing to a `.tmp` file then replacing.

## Troubleshooting

* `PermissionError` or `FileNotFoundError`: verify paths and permissions.
* `InvalidToken` during decrypt: using wrong `secret.key` or modified file.
* If encryption succeeds but decryption fails, ensure the same `secret.key` is used.


