import argparse
import getpass
import os
import sys
from vault.crypto import encrypt_target, decrypt_target, shred_file


def main():
    parser = argparse.ArgumentParser(
        prog="vault",
        description="CLI Encrypted File & Folder Vault (AES-256-GCM Chunked)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: encrypt
    enc_p = subparsers.add_parser("encrypt", help="Encrypt a file or directory into a .vault archive")
    enc_p.add_argument("target", help="Path to target file or directory")
    enc_p.add_argument("-o", "--output", help="Output .vault file path (optional)")
    enc_p.add_argument("--shred", action="store_true", help="Securely overwrite and delete source file after encryption (files only)")

    # Command: decrypt
    dec_p = subparsers.add_parser("decrypt", help="Decrypt a .vault file or archive")
    dec_p.add_argument("file", help="Path to .vault file")
    dec_p.add_argument("-o", "--output", help="Output file path (optional)")

    # Command: shred
    shred_p = subparsers.add_parser("shred", help="Overwrite and permanently delete a file")
    shred_p.add_argument("file", help="Path to target file")
    shred_p.add_argument("-p", "--passes", type=int, default=3, help="Number of overwrite passes (default: 3)")

    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            clean_target = args.target.rstrip("\\/")
            out = args.output or f"{clean_target}.vault"
            pwd = getpass.getpass("Enter Master Password: ")
            confirm = getpass.getpass("Confirm Master Password: ")
            if pwd != confirm or not pwd:
                print("[ERROR] Passwords do not match or are empty.")
                sys.exit(1)

            encrypt_target(clean_target, out, pwd)
            print(f"[OK] Encrypted output saved to: {out}")

            if args.shred:
                if os.path.isfile(clean_target):
                    shred_file(clean_target)
                    print(f"[OK] Source file shredded: {clean_target}")
                else:
                    print("[INFO] Skipping --shred because target is a directory.")

        elif args.command == "decrypt":
            if args.output:
                out = args.output
            elif args.file.endswith(".vault"):
                out = args.file[:-6]
            else:
                out = f"{args.file}.decrypted"

            pwd = getpass.getpass("Enter Master Password: ")
            result_path = decrypt_target(args.file, out, pwd)
            print(f"[OK] Decryption completed -> {result_path}")

        elif args.command == "shred":
            confirm = input(f"Permanently overwrite and delete '{args.file}'? (y/N): ")
            if confirm.lower() == "y":
                shred_file(args.file, passes=args.passes)
                print(f"[OK] File shredded: {args.file}")
            else:
                print("[ABORTED] Operation cancelled.")

    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()