Set-Content README.md @"
# Shadow Vault (``vault``)

A command-line encrypted file and directory vault written in Python using **AES-256-GCM** with **4 MB chunked streaming**, **PBKDF2-HMAC-SHA256** key derivation, and multi-pass file overwriting (``shred``).

## Features

- **Authenticated Encryption (AES-256-GCM):** Encrypts and authenticates data in 4 MB chunks using per-chunk nonces and header AAD.
- **Strong Key Derivation:** Uses PBKDF2-HMAC-SHA256 (600,000 iterations) with a random 16-byte salt per vault.
- **Large File & Folder Support:** Streams large files in 4 MB chunks and archives folders temporarily during encryption/decryption.
- **Permanent File Shredding:** Overwrites target files with random bytes across multiple passes before deleting them.
- **Standalone Windows Executable:** Distributed as a single ``vault.exe`` via GitHub Releases.

## How to Use

### 1. Using ``vault.exe`` (Windows, No Python Required)

Download ``vault.exe`` from the **Releases** section, open PowerShell in your working folder, and run:

````powershell
# Encrypt a single file
.\vault.exe encrypt .\your_file_name.txt

# Encrypt a folder
.\vault.exe encrypt .\your_folder_name -o .\your_folder_name.vault

# Encrypt and securely shred the original file
.\vault.exe encrypt .\your_file_name.txt --shred

# Decrypt a file or folder archive
.\vault.exe decrypt .\your_folder_name.vault
.\vault.exe decrypt .\your_file_name.vault -o .\restored_file_name.txt

# Permanently shred a file (default 3 passes)
.\vault.exe shred .\your_file_name.txt
.\vault.exe shred .\your_file_name.txt -p 5
