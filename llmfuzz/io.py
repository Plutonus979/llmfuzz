from __future__ import annotations

import json
import os
import random
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def decode_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def sha256_file(path: str | Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _temp_path_for(target_path: str) -> str:
    directory = os.path.dirname(target_path)
    random_token = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    return os.path.join(directory, f".tmp.{os.getpid()}.{random_token}")


def atomic_write_text(path: str | os.PathLike[str], text: str) -> None:
    path = os.fspath(path)
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp_path = _temp_path_for(path)
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes) -> None:
    path = os.fspath(path)
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp_path = _temp_path_for(path)
    with open(tmp_path, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)


def atomic_write_json(path: str | os.PathLike[str], obj: Any) -> None:
    text = json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    atomic_write_text(path, text)
