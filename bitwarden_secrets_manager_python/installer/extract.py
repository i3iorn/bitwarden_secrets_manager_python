import logging
import os
import shutil
import tempfile
import tarfile
import time
import zipfile
from pathlib import Path

from bitwarden_secrets_manager_python.utils import retry

logger = logging.getLogger(__name__)


class ExtractError(Exception):
    """Raised when archive extraction fails."""


class Extractor:
    """
    Secure extractor for .zip and .tar.gz archives.

    - Prevents path traversal.
    - Extracts atomically via a temp directory.
    - Applies safe default permissions.
    """

    def __init__(
        self,
        dir_mode: int = 0o750,
        file_mode: int = 0o640,
    ):
        self.dir_mode = dir_mode
        self.file_mode = file_mode

    @staticmethod
    def _is_within(root: Path, target: Path) -> bool:
        try:
            return str(target.resolve()).startswith(str(root.resolve()))
        except Exception:
            return False

    def _safe_extract_zip(self, archive: Path, dest: Path) -> None:
        with zipfile.ZipFile(archive, "r") as zf:
            for member in zf.namelist():
                target = dest / member
                if not self._is_within(dest, target):
                    raise ExtractError(f"Path-traversal attempt in ZIP: {member}")
            zf.extractall(dest)

    def _safe_extract_tar(self, archive: Path, dest: Path) -> None:
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                target = dest / member.name
                if not self._is_within(dest, target):
                    raise ExtractError(f"Path-traversal attempt in TAR: {member.name}")
            tf.extractall(dest)

    def _apply_permissions(self, root: Path) -> None:
        for path in root.rglob("*"):
            try:
                if path.is_dir():
                    path.chmod(self.dir_mode)
                else:
                    path.chmod(self.file_mode)
            except Exception as e:
                logger.warning(f"Failed to chmod {path}: {e}")

    @retry()
    def extract(self, archive_path: Path, extract_to: Path) -> None:
        """
        Extracts `archive_path` to `extract_to` atomically and safely.

        Raises:
            ExtractError: on any failure.
        """
        if not archive_path.exists():
            raise ExtractError(f"Archive not found: {archive_path}")

        tmp_parent = extract_to.parent or Path.cwd()
        with tempfile.TemporaryDirectory(dir=tmp_parent) as tmpdir:
            temp_extract = Path(tmpdir) / extract_to.name
            temp_extract.mkdir(parents=True, exist_ok=True)

            try:
                suffixes = archive_path.suffixes
                if suffixes[-2:] == [".tar", ".gz"]:
                    self._safe_extract_tar(archive_path, temp_extract)
                elif archive_path.suffix == ".zip":
                    self._safe_extract_zip(archive_path, temp_extract)
                else:
                    raise ExtractError(f"Unsupported archive format: {suffixes}")

                # Apply safe permissions
                self._apply_permissions(temp_extract)

                # Atomically replace existing directory
                if extract_to.exists():
                    backup = extract_to.with_suffix(".bak")
                    try:
                        extract_to.rename(backup)
                    except Exception:
                        shutil.rmtree(extract_to)
                    else:
                        shutil.rmtree(backup)

                temp_extract.rename(extract_to)

            except ExtractError:
                raise
            except Exception as e:
                raise ExtractError(f"Extraction error: {e}")
