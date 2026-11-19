import os
import shutil
import struct
import tempfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC = b"SVAULT2"
SALT_SIZE = 16
BASE_NONCE_SIZE = 12
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB per chunk
ITERATIONS = 600_000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _make_chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    idx_bytes = struct.pack(">Q", index)
    padded_idx = (b"\x00" * (BASE_NONCE_SIZE - len(idx_bytes))) + idx_bytes
    return bytes(a ^ b for a, b in zip(base_nonce, padded_idx))


def _encrypt_single_file(input_path: str, output_path: str, password: str, is_dir: bool = False) -> None:
    salt = os.urandom(SALT_SIZE)
    base_nonce = os.urandom(BASE_NONCE_SIZE)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    flags = b"\x01" if is_dir else b"\x00"
    header = MAGIC + flags + salt + base_nonce
    aad = MAGIC + flags

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(header)
        chunk_index = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            nonce = _make_chunk_nonce(base_nonce, chunk_index)
            enc_chunk = aesgcm.encrypt(nonce, chunk, associated_data=aad)
            fout.write(struct.pack(">I", len(enc_chunk)) + enc_chunk)
            chunk_index += 1


def _decrypt_single_file(input_path: str, output_path: str, password: str) -> bool:
    with open(input_path, "rb") as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Invalid file format or unsupported vault version.")

        flags = fin.read(1)
        salt = fin.read(SALT_SIZE)
        base_nonce = fin.read(BASE_NONCE_SIZE)

        if len(flags) != 1 or len(salt) != SALT_SIZE or len(base_nonce) != BASE_NONCE_SIZE:
            raise ValueError("Corrupted or incomplete vault file header.")

        is_dir = flags == b"\x01"
        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        aad = MAGIC + flags

        temp_out = output_path + ".tmp_dec"
        try:
            with open(temp_out, "wb") as fout:
                chunk_index = 0
                while True:
                    len_bytes = fin.read(4)
                    if not len_bytes:
                        break
                    if len(len_bytes) != 4:
                        raise ValueError("Corrupted chunk length header.")
                    (enc_len,) = struct.unpack(">I", len_bytes)
                    enc_chunk = fin.read(enc_len)
                    if len(enc_chunk) != enc_len:
                        raise ValueError("Truncated or corrupted encrypted chunk.")

                    nonce = _make_chunk_nonce(base_nonce, chunk_index)
                    try:
                        chunk = aesgcm.decrypt(nonce, enc_chunk, associated_data=aad)
                    except InvalidTag as exc:
                        raise ValueError("Invalid password or file has been tampered with.") from exc

                    fout.write(chunk)
                    chunk_index += 1

            if os.path.exists(output_path):
                os.remove(output_path)
            os.replace(temp_out, output_path)
        except Exception:
            if os.path.exists(temp_out):
                os.remove(temp_out)
            raise

    return is_dir


def encrypt_target(target_path: str, output_path: str, password: str) -> None:
    if not os.path.exists(target_path):
        raise FileNotFoundError(f"Target not found: {target_path}")

    if os.path.isdir(target_path):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_base = os.path.join(tmpdir, "payload")
            archive_path = shutil.make_archive(archive_base, "zip", root_dir=target_path)
            _encrypt_single_file(archive_path, output_path, password, is_dir=True)
    elif os.path.isfile(target_path):
        _encrypt_single_file(target_path, output_path, password, is_dir=False)
    else:
        raise ValueError("Unsupported target type.")


def decrypt_target(input_path: str, output_path: str, password: str) -> str:
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Vault file not found: {input_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        temp_dec_file = os.path.join(tmpdir, "decrypted_payload.bin")
        is_dir = _decrypt_single_file(input_path, temp_dec_file, password)

        if is_dir:
            extract_dir = output_path
            if os.path.exists(extract_dir):
                extract_dir = output_path + "_extracted"
            os.makedirs(extract_dir, exist_ok=True)
            shutil.unpack_archive(temp_dec_file, extract_dir=extract_dir, format="zip")
            return extract_dir

        if os.path.isdir(output_path):
            final_file = output_path + "_decrypted"
        else:
            final_file = output_path

        if os.path.exists(final_file):
            os.remove(final_file)
        shutil.move(temp_dec_file, final_file)
        return final_file


def shred_file(file_path: str, passes: int = 3) -> None:
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    file_size = os.path.getsize(file_path)
    with open(file_path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            remaining = file_size
            while remaining > 0:
                write_len = min(CHUNK_SIZE, remaining)
                f.write(os.urandom(write_len))
                remaining -= write_len
            f.flush()
            os.fsync(f.fileno())

    os.remove(file_path)