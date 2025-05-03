import hashlib
import json
import logging
import os
import platform
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

from bitwarden_secrets_manager_python.installer.download import Downloader, DownloadError
from bitwarden_secrets_manager_python.installer.extract import Extractor, ExtractError
from bitwarden_secrets_manager_python.installer.strategies import PromptStrategy, InteractivePrompt, InMemoryReturn

logger = logging.getLogger(__name__)


class BitwardenCLIInstaller:
    """
    Installs Bitwarden CLI locally from GitHub if not present at the target path.
    Uses injected Downloader and Extractor for I/O and archive handling, and PromptStrategy for user prompts.
    """

    GITHUB_API_BASE             = "https://api.github.com/repos/bitwarden/sdk-sm/releases"
    BWS_ASSET_TAG_PATTERN       = "bws-v{version}"
    ASSET_NAME_PATTERN_CLI      = "bws-{arch}-{system}-{version}.zip"
    ASSET_NAME_PATTERN_CHECKSUM = "bws-{algo}-checksums-{version}.txt"
    CHECKSUM_ALGO               = "sha256"

    def __init__(
        self,
        target_path: Path,
        downloader: Downloader = Downloader(),
        extractor: Extractor = Extractor(),
        prompt: PromptStrategy = InteractivePrompt(),
        silent: bool = False,
        version: Optional[str] = "1.0.0",
        checksum_algo: str = CHECKSUM_ALGO,
    ):
        self.target_path = target_path.resolve()
        self.downloader = downloader
        self.extractor = extractor
        self.prompt = prompt
        self.silent = silent
        self.version = version
        self.checksum_algo = checksum_algo
        self.system, self.arch = self._detect_platform()

    def ensure(self) -> bool:
        """
        Ensures the CLI exists at the configured path. Installs it if missing.

        Returns:
            True if CLI is ready to use, False otherwise.
        """
        if self.target_path.exists() and os.access(self.target_path, os.X_OK):
            logger.debug(f"Bitwarden CLI found at {self.target_path}")
            return True

        if not self.silent and not self.prompt.confirm(
            f"Bitwarden CLI not found at {self.target_path}. Download and install?"
        ):
            return False

        try:
            releases = self._fetch_release_data()
            if not releases:
                raise RuntimeError("No release data found")

            asset_url, asset_name, checksum = self._find_asset_and_checksum(releases)
            if not (asset_url and asset_name and checksum):
                raise RuntimeError("Required assets not found in release data.")

            logger.debug(f"Asset URL: {asset_url}, Name: {asset_name}, Checksum: {checksum}")

            with tempfile.TemporaryDirectory() as tmp:
                tmp_dir = Path(tmp)
                archive_path = tmp_dir / asset_name

                self.downloader.download(asset_url, archive_path, return_strategy=InMemoryReturn())

                if not self._verify_checksum(archive_path, checksum):
                    raise ValueError("Checksum verification failed")

                self.extractor.extract(archive_path, tmp_dir)

                binary_path = self._locate_binary(tmp_dir)
                if not binary_path:
                    raise FileNotFoundError("Could not locate 'bw' binary in archive")

                self._install_binary(binary_path)
                return True

        except (DownloadError, ExtractError) as e:
            print(f"[ERROR] Installation failed: {e}")
            return False

    def _detect_platform(self) -> Tuple[str, str]:
        system = platform.system().lower()
        arch = platform.machine().lower()

        arch_map = {"amd64": "x86_64", "x86_64": "x86_64", "x86": "i686", "i386": "i686"}
        if arch not in arch_map:
            raise RuntimeError(f"Unsupported architecture: {arch}")

        mapping = {"windows": "pc-windows-msvc", "linux": "unknown-linux-gnu", "darwin": "apple-darwin"}
        if system not in mapping:
            raise RuntimeError(f"Unsupported platform: {system}")

        return mapping[system], arch_map[arch]

    def _fetch_release_data(self) -> List[Dict]:
        logger.debug(f"Fetching release data for {self.target_path}")

        url = self.GITHUB_API_BASE
        logger.debug(f"Release URL: {url}")

        try:
            text = self.downloader.download(url)
            logger.debug(f"Release data: {text[:100]}")
        except DownloadError as e:
            raise RuntimeError(f"Failed to fetch release data: {e}")

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON from GitHub API: {text[:100]}")
            raise RuntimeError(f"Invalid JSON from GitHub API: {e}")

    def _find_asset_and_checksum(self, releases: List[Dict[str, Any]]) -> tuple[str, str, str]:
        for release in releases:
            logger.debug(f"Checksum for {release['tag_name']} -- {self.BWS_ASSET_TAG_PATTERN.format(version=self.version)}")
            if release.get("tag_name", "") == self.BWS_ASSET_TAG_PATTERN.format(
                version=self.version
            ):
                assets = release.get("assets", [])
                break
        else:
            raise RuntimeError("No matching release found")

        checksum_file_url = None
        binary_url = None
        binary_name = None

        for asset in assets:
            logger.debug(f"Asset: {asset['name']} -- {self.ASSET_NAME_PATTERN_CLI.format(arch=self.arch, system=self.system, version=self.version)}")
            if asset.get("name", "").endswith(self.ASSET_NAME_PATTERN_CHECKSUM.format(
                algo=self.checksum_algo, version=self.version
            )):
                checksum_file_url = asset.get("browser_download_url")
                logger.debug(f"Checksum File URL: {checksum_file_url}")
            elif asset.get("name", "").endswith(self.ASSET_NAME_PATTERN_CLI.format(
                arch=self.arch, system=self.system, version=self.version
            )):
                binary_url = asset.get("browser_download_url")
                binary_name = asset.get("name")
                logger.debug(f"Binary URL: {binary_url}, Name: {binary_name}")

        if not (binary_url and checksum_file_url and binary_name):
            raise RuntimeError("Required assets not found in release data.")

        checksum_text = self.downloader.download(checksum_file_url)
        expected = self._parse_checksum_text(checksum_text, binary_name)
        return binary_url, binary_name, expected

    def _parse_checksum_text(self, text: str, filename: str) -> str:
        for line in text.splitlines():
            parts = line.strip().split()
            if len(parts) == 2 and parts[1].endswith(filename):
                return parts[0].lower()
        raise ValueError(f"Checksum for {filename} not found.")

    def _verify_checksum(self, path: Path, expected: str) -> bool:
        sha = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest().lower() == expected.lower()

    def _locate_binary(self, root: Path) -> Optional[Path]:
        for p in root.rglob("bw*"):
            if p.is_file() and os.access(p, os.X_OK):
                return p
        return None

    def _install_binary(self, binary_path: Path) -> None:
        self.target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(binary_path), str(self.target_path))
        self.target_path.chmod(0o755)
