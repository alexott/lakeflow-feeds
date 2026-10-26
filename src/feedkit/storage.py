"""Small file storage abstraction over a UC volume (FUSE path or Files API)."""
from __future__ import annotations

import io
import os
import tempfile
from pathlib import Path
from typing import Protocol


class Storage(Protocol):
    def read_text(self, path: str) -> str | None: ...
    def write_text(self, path: str, text: str) -> None: ...
    def write_bytes(self, path: str, data: bytes) -> None: ...
    def exists(self, path: str) -> bool: ...
    def listdir(self, path: str) -> list[str]: ...
    def move(self, src: str, dst: str) -> None: ...


class PathStorage:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _p(self, path: str) -> Path:
        return self.root / path

    def read_text(self, path: str) -> str | None:
        p = self._p(path)
        return p.read_text() if p.exists() else None

    def write_bytes(self, path: str, data: bytes) -> None:
        p = self._p(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".tmp-")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, p)

    def write_text(self, path: str, text: str) -> None:
        self.write_bytes(path, text.encode())

    def exists(self, path: str) -> bool:
        return self._p(path).exists()

    def listdir(self, path: str) -> list[str]:
        p = self._p(path)
        return [c.name for c in p.iterdir() if not c.name.startswith(".tmp-")] if p.is_dir() else []

    def move(self, src: str, dst: str) -> None:
        d = self._p(dst)
        d.parent.mkdir(parents=True, exist_ok=True)
        os.replace(self._p(src), d)


class FilesApiStorage:
    def __init__(self, client, root: str):
        self.client, self.root = client, root.rstrip("/")

    def _p(self, path: str) -> str:
        return f"{self.root}/{path}"

    def read_text(self, path: str) -> str | None:
        from databricks.sdk.errors import NotFound
        try:
            return self.client.files.download(self._p(path)).contents.read().decode()
        except NotFound:
            return None

    def write_bytes(self, path: str, data: bytes) -> None:
        self.client.files.upload(self._p(path), io.BytesIO(data), overwrite=True)

    def write_text(self, path: str, text: str) -> None:
        self.write_bytes(path, text.encode())

    def exists(self, path: str) -> bool:
        from databricks.sdk.errors import NotFound
        try:
            self.client.files.get_metadata(self._p(path))
            return True
        except NotFound:
            return False

    def listdir(self, path: str) -> list[str]:
        from databricks.sdk.errors import NotFound
        try:
            return [e.name for e in self.client.files.list_directory_contents(self._p(path))]
        except NotFound:
            return []

    def move(self, src: str, dst: str) -> None:
        data = self.client.files.download(self._p(src)).contents.read()
        self.write_bytes(dst, data)
        self.client.files.delete(self._p(src))
