import os
import base64
from concurrent.futures import ProcessPoolExecutor
from cryptography.fernet import Fernet

# --------- Key Management ---------

def load_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)
    else:
        with open("secret.key", "rb") as f:
            key = f.read()
    return Fernet(key)

# --------- Encryption / Decryption ---------

def encrypt_file(path):
    fernet = load_key()
    out_path = path.replace(".txt", "_encrypted.txt")

    try:
        with open(path, "rb") as f:
            data = f.read()

        encrypted_bytes = fernet.encrypt(data)
        encrypted_text = base64.b64encode(encrypted_bytes).decode()

        with open(out_path, "w") as f:
            f.write(encrypted_text)

        return f"[OK] Encrypted → {out_path}"

    except Exception as e:
        return f"[ERR] {path}: {e}"


def decrypt_file(path):
    fernet = load_key()
    out_path = path.replace("_encrypted.txt", "_decrypted.txt")

    try:
        with open(path, "r") as f:
            encrypted_text = f.read()

        encrypted_bytes = base64.b64decode(encrypted_text.encode())
        decrypted = fernet.decrypt(encrypted_bytes)

        with open(out_path, "wb") as f:
            f.write(decrypted)

        return f"[OK] Decrypted → {out_path}"

    except Exception as e:
        return f"[ERR] {path}: {e}"

# --------- Parallel Runner ---------

def run_parallel(files, mode="encrypt", workers=4):
    with ProcessPoolExecutor(max_workers=workers) as exe:
        if mode == "encrypt":
            results = exe.map(encrypt_file, files)
        else:
            results = exe.map(decrypt_file, files)
    print("\n".join(results))



if __name__ == "__main__":
    # files_list = []

    print("1) Encrypt")
    print("2) Decrypt")
    choice = input("Choose: ")
    files_list = input("Enter file paths separated by spaces: ").split()


    if choice == "1":
        run_parallel(files_list, mode="encrypt")
    else:
        run_parallel(files_list, mode="decrypt")
