def save_encrypted_message(path, encrypted_bytes):
    with open(path, "ab") as f:
        f.write(encrypted_bytes + b"\n")
