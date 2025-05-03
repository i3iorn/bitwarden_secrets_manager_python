import logging
import os
from pathlib import Path
from typing import Optional, List, Dict

from bitwarden_secrets_manager_python.core import BitwardenCLI
from bitwarden_secrets_manager_python.core.managers import ConfigManager, SessionManager
from bitwarden_secrets_manager_python.installer import BitwardenCLIInstaller
from bitwarden_secrets_manager_python.projects import ProjectManager
from bitwarden_secrets_manager_python.secrets import SecretsCache, SecretManager

logger = logging.getLogger(__name__)


class BWS:
    def __init__(self, bws_access_token: Optional[str] = None, bws_path: Optional[str] = None, cache_duration: Optional[int] = 60, silent_install: bool = False) -> None:
        bws_path = bws_path or os.getenv("BWS_PATH", "../bws.exe")
        bws_access_token = bws_access_token or os.getenv("BWS_ACCESS_TOKEN", "")

        if not bws_path or not bws_access_token:
            raise ValueError("Both BWS_PATH and BWS_ACCESS_TOKEN must be provided or set as environment variables.")
        if len(bws_access_token) < 20:
            raise ValueError("Access token length suspiciously short")

        self.installer = BitwardenCLIInstaller(Path(bws_path), silent=silent_install)
        self.installer.ensure()
        self.cli = BitwardenCLI(bws_path, bws_access_token)
        self.cache = SecretsCache(cache_duration)
        self.project_manager = ProjectManager(self.cli)
        self.secret_manager = SecretManager(self.cli, self.cache)
        self.config = ConfigManager(self.cli)
        self.session = SessionManager(self.cli)

    def help(self) -> None:
        """Displays help information for Bitwarden CLI."""
        return self.cli.execute(['--help'], parse_json=False)

    def get_secret(self, key: str) -> dict:
        """Fetches a secret from the cache or Bitwarden."""
        logger.debug(f"Getting secret '{key}'")
        return self.secret_manager.get_secret(key)

    def list_secrets(self) -> List[Dict]:
        """Lists all secrets."""
        logger.debug("Listing all secrets")
        return self.secret_manager.list_secrets()

    def add_secret(self, key: str, value: str) -> None:
        """Adds a new secret."""
        logger.debug(f"Adding secret '{key}' with value '{value}'")
        self.secret_manager.add_secret(key, value)

    def list_projects(self) -> List[Dict]:
        """Lists all projects."""
        logger.debug("Listing all projects")
        return self.project_manager.list_projects()

    def create_project(self, project_id: str) -> Dict:
        """Creates a new project."""
        logger.debug(f"Creating project '{project_id}'")
        return self.project_manager.create_project(project_id)

    def login(self, username: str, password: str) -> None:
        """Logs into Bitwarden."""
        logger.debug(f"Logging in with username '{username}'")
        self.session.login(username, password)

    def logout(self) -> None:
        """Logs out of Bitwarden."""
        logger.debug("Logging out")
        self.session.logout()
