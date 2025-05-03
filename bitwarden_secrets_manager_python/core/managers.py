from getpass import getpass
from typing import Optional, ContextManager

from bitwarden_secrets_manager_python import BitwardenCLI
from bitwarden_secrets_manager_python.core import logger


class ConfigManager:
    """Handles 'bw config' commands with validation."""
    def __init__(self, cli: BitwardenCLI):
        self.cli = cli

    def set(self, key: str, value: str, profile: Optional[str] = None) -> None:
        if not key.isidentifier():
            raise ValueError(f"Invalid config key: {key}")
        args = ["config", "set", key, value]
        if profile:
            args += ["--profile", profile]
        self.cli.execute(args, parse_json=False)

    def get(self, key: str, profile: Optional[str] = None) -> str:
        if not key.isidentifier():
            raise ValueError(f"Invalid config key: {key}")
        args = ["config", "get", key]
        if profile:
            args += ["--profile", profile]
        return self.cli.execute(args, parse_json=False)


class SessionManager(ContextManager["SessionManager"]):
    """Manages login/logout, usable as a context manager."""
    def __init__(self, cli: BitwardenCLI):
        self.cli = cli
        self.token: Optional[str] = None

    def __enter__(self) -> "SessionManager":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.logout()

    def login(self, username: str, password: Optional[str] = None) -> str:
        if password is None:
            password = getpass("Bitwarden Password: ")
        args = ["login", "--username", username, "--raw"]
        resp = self.cli.execute(args, input_data=password + "\n")
        if isinstance(resp, str):
            self.token = resp
        else:
            self.token = resp.get("access_token")
        if not self.token:
            raise RuntimeError("Login failed, no token")
        self.cli.secrets.append(self.token)
        logger.info("Logged in successfully.")
        return self.token

    def logout(self) -> None:
        self.cli.execute(["logout"], parse_json=False)
        logger.info("Logged out.")
        self.token = None
