import logging
import os
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Protocol, Optional

from bitwarden_secrets_manager_python.installer.types import ProgressCallback, DT

logger = logging.getLogger(__name__)


class PromptStrategy(Protocol):
    def confirm(self, message: str) -> bool: ...

class InteractivePrompt:
    def confirm(self, message): return input(message + " [y/N] ").lower() == "y"

class NonInteractivePrompt:
    def confirm(self, message): return True


class CacheStrategy(ABC):
    @abstractmethod
    def read(self, key: str) -> Optional[bytes]: ...
    @abstractmethod
    def write(self, key: str, data: bytes) -> None: ...

    def __bool__(self):
        return True if self.read("test") else False


class StorageStrategy(ABC):
    @abstractmethod
    def prepare(self, dest: Path) -> Path: ...
    @abstractmethod
    def commit(self, tmp: Path, final: Path) -> None: ...


class ReturnStrategy(ABC):
    @abstractmethod
    def handle(
        self,
        resp: "http.client.HTTPResponse",
        report_progress: ProgressCallback,
        chunk_size: int
    ) -> DT: ...


class NoCache(CacheStrategy):
    def read(self, key: str) -> Optional[bytes]:
        return None
    def write(self, key: str, data: bytes) -> None:
        pass


class FileCache(CacheStrategy):
    def __init__(self, cache_dir: Path):
        self.dir = cache_dir
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.Lock()

    def _path(self, key: str) -> Path:
        return self.dir / f"{key}.bin"

    def read(self, key: str) -> Optional[bytes]:
        p = self._path(key)
        return p.read_bytes() if p.exists() else None

    def write(self, key: str, data: bytes) -> None:
        tmp = self._path(key).with_suffix(".tmp")
        with self.lock:
            tmp.write_bytes(data)
            os.replace(tmp, self._path(key))
            self._path(key).chmod(0o600)


class AtomicFileStorage(StorageStrategy):
    def prepare(self, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        return dest.with_suffix(dest.suffix + ".tmp")
    def commit(self, tmp: Path, final: Path) -> None:
        os.replace(tmp, final)
        final.chmod(0o750)


class InMemoryReturn(ReturnStrategy):
    def handle(self, resp, report_progress, chunk_size):
        logger.debug("Using InMemoryReturn")
        total = resp.getheader("Content-Length")
        total_n = int(total) if total and total.isdigit() else None
        buf = bytearray()

        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            buf.extend(chunk)
            report_progress(len(buf), total_n)

        return bytes(buf)


class StreamingReturn(ReturnStrategy):
    def handle(self, resp, report_progress, chunk_size):
        logger.debug("Using StreamingReturn")
        total = resp.getheader("Content-Length")
        total_n = int(total) if total and total.isdigit() else None
        downloaded = 0

        for chunk in iter(lambda: resp.read(chunk_size), b""):
            downloaded += len(chunk)
            report_progress(downloaded, total_n)
            yield chunk


class TextReturn(ReturnStrategy):
    def __init__(self, encoding: str = "utf-8"):
        self.encoding = encoding

    def handle(self, resp, report_progress, chunk_size):
        logger.debug(f"Using TextReturn with encoding: {self.encoding}")
        total = resp.getheader("Content-Length")
        total_n = int(total) if total and total.isdigit() else None
        buf = bytearray()

        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            buf.extend(chunk)
            report_progress(len(buf), total_n)

        return buf.decode(self.encoding)
