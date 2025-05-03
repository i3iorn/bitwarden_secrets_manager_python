import json
import logging
import time
from typing import List, Dict, Any, Optional, Union
from bitwarden_secrets_manager_python.core import BitwardenCLI
from bitwarden_secrets_manager_python.core.utils import BWObjects

logger = logging.getLogger(__name__)


class SecretManager:
    def __init__(self, cli: BitwardenCLI, cache: 'SecretsCache'):
        self.cli = cli
        self.cache = cache

    def list_secrets(self, print_to_console: bool = False) -> List[Dict]:
        response = self.cli.execute([BWObjects.SECRET, 'list'])
        if print_to_console:
            print(response)
        return response

    def get_secret(self, secret_id: str, print_to_console: bool = False) -> Dict:
        response = self.cli.execute([BWObjects.SECRET, 'get', secret_id])
        if print_to_console:
            print(response)
        return response

    def add_secret(self, name: str, value: str, print_to_console: bool = False) -> Dict:
        payload = json.dumps({"name": name, "value": value})
        response = self.cli.execute([BWObjects.SECRET, 'create', payload])
        if print_to_console:
            print(response)
        return response

    def update_secret(self, secret_id: str, fields: Dict[str, Any], print_to_console: bool = False) -> Dict:
        payload = json.dumps(fields)
        response = self.cli.execute([BWObjects.SECRET, 'edit', secret_id, payload])
        if print_to_console:
            print(response)
        return response

    def delete_secret(self, secret_id: str, print_to_console: bool = False) -> None:
        self.cli.execute([BWObjects.SECRET, 'delete', secret_id], parse_json=False)
        if print_to_console:
            print(f"Deleted secret {secret_id}")


class SecretsCache:
    def __init__(self, cache_duration: Optional[int] = 60):
        self._secrets: Dict[str, Dict] = {}
        self.cache_duration = cache_duration  # Time in seconds
        self._last_cache_refresh = 0

    def refresh_cache(self, force_refresh: bool = False) -> None:
        """Refreshes the secrets cache if it is stale."""
        if force_refresh or self._is_secret_stale():
            logger.info("Refreshing secrets cache...")
            self._secrets = {}  # Ideally, you'd pull this from Bitwarden, but here it's just reset
            self._last_cache_refresh = time.time()

    def _is_secret_stale(self) -> bool:
        """Checks if the secrets cache is stale."""
        return time.time() - self._last_cache_refresh > self.cache_duration

    def get_secret(self, key: str, value_only: bool = False) -> Union[str, Dict]:
        """Gets a secret from the cache."""
        self.refresh_cache()
        secret = self._secrets.get(key)
        if secret:
            return secret['value'] if value_only else secret
        else:
            return None
