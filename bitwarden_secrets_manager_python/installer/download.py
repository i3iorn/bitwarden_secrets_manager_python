import hashlib
import io
import logging
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Generator, Optional, Union

from bitwarden_secrets_manager_python.installer.strategies import CacheStrategy, StorageStrategy, ReturnStrategy, \
    NoCache, FileCache, AtomicFileStorage, StreamingReturn, TextReturn
from bitwarden_secrets_manager_python.installer.types import ProgressCallback
from bitwarden_secrets_manager_python.utils import retry

logger = logging.getLogger(__name__)


class DownloadError(Exception):
    """Raised when a download fails."""



class Downloader:
    def __init__(
        self,
        timeout: float = 15.0,
        cache: CacheStrategy = None,
        storage: StorageStrategy = None,
        progress_callback: Optional[ProgressCallback] = None,
        user_agent: str = "downloader/1.0",
    ):
        self.timeout = timeout
        self.cache = cache or NoCache()
        self.storage = storage or AtomicFileStorage()
        self.progress = progress_callback
        self.user_agent = user_agent
        self.opener = urllib.request.build_opener()
        self._etag_lock = threading.Lock()

    def _hash(self, url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()

    def _report(self, got: int, total: Optional[int]):
        if self.progress:
            self.progress(got, total)

    def _etag_path(self, key: str) -> Path:
        # same cache dir as FileCache
        return (self.cache.dir if isinstance(self.cache, FileCache) else Path.cwd() / "cache") / f"{key}.etag"

    def _read_etag(self, key: str) -> Optional[str]:
        p = self._etag_path(key)
        return p.read_text().strip() if p.exists() else None

    def _write_etag(self, key: str, etag: str) -> None:
        p = self._etag_path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        with self._etag_lock:
            tmp.write_text(etag)
            os.replace(tmp, p)
            p.chmod(0o600)

    def download(
        self,
        url: str,
        dest: Optional[Path] = None,
        *,
        return_strategy: ReturnStrategy = TextReturn(),
        chunk_size: int = 64 * 1024,
    ) -> Union[bytes, str, Generator[bytes, None, None]]:
        """
        Dispatch to streaming vs. non-streaming download based on the strategy.
        """
        if isinstance(return_strategy, StreamingReturn):
            # generator path
            return self._download_stream(url, return_strategy, chunk_size)
        else:
            # direct return path
            return self._download_sync(url, dest, return_strategy, chunk_size)

    @retry(exceptions=(DownloadError,), retries=3, delay=1)
    def _download_sync(
            self,
            url: str,
            dest: Optional[Path],
            return_strategy: ReturnStrategy,
            chunk_size: int
    ) -> Union[bytes, str]:
        """
        Non‐streaming download that returns bytes or str via the provided ReturnStrategy.
        """
        key = self._hash(url)

        # 1) Cache hit?
        data = self.cache.read(key)
        if data is not None:
            logger.debug("Cache hit (sync)")
            # Build a fake response for the strategy
            FakeResp = type(
                "FakeResp",
                (),
                {
                    "getheader": lambda self, *a, **k: None,
                    "read": lambda self, n=-1: data
                }
            )
            result = return_strategy.handle(FakeResp(), self._report, chunk_size)
            # If dest is provided, write out
            if dest:
                if isinstance(result, bytes):
                    dest.write_bytes(result)
                else:
                    dest.write_text(result)
            return result

        # 2) Prepare atomic file write
        final = dest or Path(f"{key}.bin")
        tmp = self.storage.prepare(final)

        # 3) Build request with ETag
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        if self.cache:
            if et := self._read_etag(key):
                req.add_header("If-None-Match", et)

        # 4) Issue request, catch 304 as cache
        try:
            resp = self.opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                logger.debug("Not modified (304), using cache (sync)")
                data = self.cache.read(key)
                if data is None:
                    raise DownloadError("304 but no cache!") from e
                FakeResp = type(
                    "FakeResp",
                    (),
                    {
                        "getheader": lambda self, *a, **k: None,
                        "read": lambda self, n=-1: data
                    }
                )
                return return_strategy.handle(FakeResp(), self._report, chunk_size)
            raise DownloadError(f"HTTP {e.code} for {url}") from e

        # 5) Process real response
        with resp:
            result = return_strategy.handle(resp, self._report, chunk_size)
            if new_et := resp.getheader("ETag"):
                self._write_etag(key, new_et)

        # 6) Commit to disk & cache
        raw = result if isinstance(result, bytes) else result.encode()
        if dest:
            tmp.write_bytes(raw)
            self.storage.commit(tmp, dest)
        self.cache.write(key, raw)

        return result

    @retry(exceptions=(DownloadError,), retries=3, delay=1)
    def _download_stream(
            self,
            url: str,
            return_strategy: StreamingReturn,
            chunk_size: int
    ) -> Generator[bytes, None, None]:
        """
        Streaming download that yields chunks via StreamingReturn.handle().
        """
        key = self._hash(url)

        # 1) Cache hit?
        data = self.cache.read(key)
        if data is not None:
            logger.debug("Cache hit (stream)")
            buf = io.BytesIO(data)
            for chunk in return_strategy.handle(buf, self._report, chunk_size):
                yield chunk
            return

        # 2) Build request with ETag
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        if self.cache:
            if et := self._read_etag(key):
                req.add_header("If-None-Match", et)

        # 3) Issue request, catch 304 as cache
        try:
            resp = self.opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                logger.debug("Not modified (304), using cache (stream)")
                data = self.cache.read(key)
                if data is None:
                    raise DownloadError("304 but no cache!") from e
                buf = io.BytesIO(data)
                for chunk in return_strategy.handle(buf, self._report, chunk_size):
                    yield chunk
                return
            raise DownloadError(f"HTTP {e.code} for {url}") from e

        # 4) Stream real response
        with resp:
            buffer = bytearray()
            for chunk in return_strategy.handle(resp, self._report, chunk_size):
                buffer.extend(chunk)
                yield chunk

            if new_et := resp.getheader("ETag"):
                self._write_etag(key, new_et)
            self.cache.write(key, bytes(buffer))
