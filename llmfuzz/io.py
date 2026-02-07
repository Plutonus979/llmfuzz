import json
import os
import random
import string


def sha256_file(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _temp_path_for(target_path):
    directory = os.path.dirname(target_path)
    random_token = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    return os.path.join(directory, f".tmp.{os.getpid()}.{random_token}")


def atomic_write_text(path, text):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp_path = _temp_path_for(path)
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)


def atomic_write_bytes(path, data):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp_path = _temp_path_for(path)
    with open(tmp_path, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)


def atomic_write_json(path, obj):
    text = json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    atomic_write_text(path, text)
