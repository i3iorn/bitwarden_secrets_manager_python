"""
Original source found at jdhalbert/bitwarden_secrets_manager_python
"""

import time
import os
import json
import logging
import subprocess
from threading import Lock
from pathlib import Path
from copy import deepcopy
from typing import Type

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


CACHE_DURATION_DEFAULT = 300


class BWSException(Exception):
    """Base class for BWS exceptions."""
    pass


class BWSExecutableNotFound(BWSException):
    """Raised when the Bitwarden CLI executable is not found."""
    pass


class BWSInvalidProjectName(BWSException):
    """Raised when the project name is invalid."""
    pass


class BWSProjectCreateFailed(BWSException):
    """Raised when the project creation fails."""
    pass


class BWSProjectExists(BWSException):
    """Raised when the project name already exists."""
    pass


class BWSProjectNotFound(BWSException):
    """Raised when the project name is not found."""
    pass


class BWSAccessTokenNotFound(BWSException):
    """Raised when the access token is not found."""
    pass


class BWSKeyExistsException(BWSException):
    """Raised when the key already exists in the project."""
    pass


class BWSKeyInvalid(BWSException):
    """Raised when the key is invalid."""
    pass


class BWSKeyNotFound(BWSException):
    """Raised when the key is not found."""
    pass


class BWSKeyUpdateFailed(BWSException):
    """Raised when the key update fails."""
    pass


class BWSKeyDeleteFailed(BWSException):
    """Raised when the key delete fails."""
    pass


class BWSKeyCreateFailed(BWSException):
    """Raised when the key creation fails."""
    pass


class BWSKeyListFailed(BWSException):
    """Raised when the key list fails."""
    pass


class BWSKeyEditFailed(BWSException):
    """Raised when the key edit fails."""
    pass


class BWSExecutionException(BWSException):
    """Raised when the Bitwarden CLI command execution fails."""
    pass


class BWS:
    """
    A Python wrapper for managing secrets with Bitwarden CLI (bws).

    This class provides methods to interact with the Bitwarden Secrets Manager, allowing for
    secret retrieval, addition, update, and deletion, with caching capabilities.
    """
    def __init__(
            self,
            project_name: str = None,
            bws_access_token: str = None,
            bws_path: str = None,
            log_level: int = logging.WARNING,
            cache_duration: int = None
    ) -> None:
        """
        Initialize the BWS object. The project name and Bitwarden CLI access token can be provided as arguments or
        set as environment variables. The Bitwarden CLI executable path can be provided as an argument or set as an
        environment variable. The logging level can be set as an argument. The cache duration can be set as an argument
        or set as an environment variable. If neither is provided, the default cache duration is 300 seconds.

        :param project_name: The name of the project. Defaults to None.
        :type project_name: str
        :param bws_access_token: The access token for Bitwarden CLI. Defaults to None.
        :type bws_access_token: str
        :param bws_path: The path to the Bitwarden CLI executable. Defaults to None.
        :type bws_path: str
        :param log_level: The logging level. Defaults to logging.WARNING.
        :type log_level: int
        :param cache_duration: The duration in seconds to cache secrets. Defaults to None.
        :type cache_duration: int

        :raises BWSExecutableNotFound: If the Bitwarden CLI executable is not found at the provided path.
        :raises ValueError: If no access token is provided or found in environment variables.
        :raises ValueError: If the project name is not found.

        :return: None
        """
        self.project_name = project_name or os.getenv('BWS_PROJECT_NAME')
        self.bws_application_path = bws_path or os.getenv('BWS_APPLICATION_PATH', "bws")
        if not Path(self.bws_application_path).is_file():
            raise BWSExecutableNotFound(f"Bitwarden CLI executable not found at path: {self.bws_application_path}")

        self.access_token = self._set_access_token(bws_access_token or os.getenv('BWS_ACCESS_TOKEN'))
        self.project_id = self._fetch_project_id()
        self.secrets_cache = {}
        self.last_cache_refresh = 0
        self.cache_duration = cache_duration or int(os.getenv('BWS_CACHE_DURATION', CACHE_DURATION_DEFAULT))
        self._lock = Lock()
        self._last_cache_refresh = time.time()
        self.refresh_secrets_cache()

        logger.setLevel(log_level)
        logger.info(f"Initialized BWS with project: {self.project_name}")

    def __getitem__(self, key: str) -> str:
        """
        When accessing the BWS object like a dictionary, only the 'value' field for the given key is returned.

        :param key: Secret name.
        :type key: str
        :return: Secret value.
        :rtype: str

        :raises BWSInvalid: If the provided key is invalid.

        :return str: Secret value.
        """
        if not self._validate_secret_key(key):
            raise BWSKeyInvalid(f"Invalid key: {key}")

        if self._is_secret_stale(key):
            logger.info(f"Refreshing secrets cache at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
            self.refresh_secrets_cache()

        return self.get_secret(key=key, value_only=True)

    def __setitem__(self, key: str, value: str) -> None:
        """Adds or updates the provided key/value pair.

        :param key: The secret key.
        :type key: str
        :param value: The secret value.
        :type value: str

        :return: None
        """
        if key in self:
            self.update_secret_value(key=key, value=value)
        else:
            self.add_secret(key=key, value=value)

    def __len__(self) -> int:
        """
        Returns the number of secrets in the project.

        :return: The number of secrets.
        :rtype: int
        """
        return len(self._secrets)

    def __contains__(self, key) -> bool:
        """
        Check if the key exists in the secrets cache.

        :param key: The secret key.
        :type key: str
        :return: True if the key exists, False otherwise.
        """
        return key in self._secrets

    def __delitem__(self, key) -> None:
        """
        Delete the secret with the provided key.

        :param key: The secret key.
        :return: None
        """
        self.delete_secret(key=key)

    def __enter__(self) -> "BWS":
        """
        Enter the context manager.

        :return: The BWS object.
        """
        self._lock.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit the context manager. If an exception occurred, log it and return False.

        :param exc_type:
        :param exc_val:
        :param exc_tb:

        :return: True if no exception occurred, False otherwise.
        """
        self._lock.release()
        if exc_type:
            logger.error(f"Exception occurred: {exc_val}")
            return False
        return True

    @staticmethod
    def _set_access_token(bws_access_token: str | None) -> str:
        """
        Sets the access token for Bitwarden CLI.

        :param bws_access_token: The access token.
        :type bws_access_token: str | None

        :return: The access token.
        :rtype: str

        :raises BWSAccessTokenNotFound: If no access token is provided or found in environment variables.
        """
        if bws_access_token:
            return bws_access_token
        elif "BWS_ACCESS_TOKEN" in os.environ:
            logger.info("Using BWS_ACCESS_TOKEN from environment variable.")
            return os.environ["BWS_ACCESS_TOKEN"]
        else:
            raise BWSAccessTokenNotFound("No BWS_ACCESS_TOKEN provided or set as environment variable. Please set "
                             "the BWS_ACCESS_TOKEN environment variable.")

    def _fetch_project_id(self) -> str:
        """
        Retrieves the project ID based on the project name.

        :return: The project ID.
        :rtype: str

        :raises BWSProjectNotFound: If the project name is not found.
        """
        projects: str | dict | list = self._call_bws(["project", "list"], as_json=True)

        for project in projects:
            logger.debug(f"Found project: {project}")
            if project["name"] == self.project_name:
                return project["id"]
        raise BWSProjectNotFound(f'Project "{self.project_name}" not found.')

    def _call_bws(self, cl_args: list[str], as_json: bool = True, print_to_console: bool = False) -> str | dict | list:
        """
        Executes a Bitwarden CLI command and returns the output.

        :param cl_args: The CLI arguments to pass to Bitwarden CLI.
        :type cl_args: list[str]
        :param as_json: Whether to parse the output as JSON. Defaults to True.
        :type as_json: bool
        :param print_to_console: Whether to print the output to the console. Defaults to False.
        :type print_to_console: bool

        :return: The output of the Bitwarden CLI command.
        :rtype: str | dict | list

        :raises BWSExecutionException: If the command execution fails.
        """
        try:
            logger.debug(f"Calling Bitwarden CLI with args: {cl_args}")
            output = subprocess.check_output(
                [self.bws_application_path] + cl_args + ["-c", "no", "-t", self.access_token],
                text=True,
                stderr=subprocess.STDOUT,
            )
            logger.debug(f"Bitwarden CLI call succeeded: {output}")
            if print_to_console:
                print(json.dumps(json.loads(output), indent=4))
            return json.loads(output) if as_json else output
        except subprocess.CalledProcessError as error:
            self._handle_subprocess_error(error)

    @staticmethod
    def _handle_subprocess_error(error: subprocess.CalledProcessError) -> None:
        logger.critical(f"Subprocess call failed with error: {error.output}, command: {error.cmd}")
        raise BWSExecutionException(f"Command execution failed: {error.cmd}, output: {error.output}")

    def _get_secrets_from_bws(self) -> dict[str, dict[str, str]]:
        """Get list of all secrets from `bws` CLI.

        :return: Dictionary of secrets keyed by key.
        :type: dict[str, dict[str, str]]

        :raises BWSKeyExistsException: If the project contains multiple keys with the same name.

        # Example return value:
        {'secret_1':
            {'id': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
            'organizationId': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
            'projectId': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
            'key': 'secret_1',
            'value': 'secret_1_value',
            'note': '',
            'creationDate': '2001-01-01T01:23:45.678901234Z',
            'revisionDate': '2001-01-01T01:23:45.678901234Z'},
        ...
        }
        """
        secrets: str | dict | list = self.call_and_return_text(cl_args=["secret", "list", self.project_id], as_json=True)
        secrets_keyed_by_key = {secret["key"]: secret for secret in secrets}
        if len(secrets_keyed_by_key) != len(secrets):
            raise BWSKeyExistsException(
                "Projects with multiple keys with the same name are not supported. Each key name in your "
                "project must be unique."
            )
        return secrets_keyed_by_key

    def _is_secret_stale(self, key: str) -> bool:
        """
        Check if the secret is stale based on the last updated time.

        :param key: The secret key.
        :type key: str
        :return: True if the secret is stale, False otherwise.
        :rtype: bool
        """
        try:
            secret_last_updated: str = self._secrets[key].get('revisionDate')
        except KeyError:
            return True

        if not secret_last_updated:
            return True
        return (time.time() - time.strptime(secret_last_updated)) > self.cache_duration

    @staticmethod
    def _validate_secret_key(key: str) -> bool:
        """
        Validate the secret key.

        :param key: The secret key.
        :type key: str
        :return: True if the key is valid, False otherwise.
        :rtype: bool
        """
        return isinstance(key, str) and key.isalnum() and 1 <= len(key) <= 40

    def _attempt_cache_refresh(self, force_refresh: bool) -> None:
        """
        Attempt to refresh the secrets cache.

        :param force_refresh: Whether to force a refresh.
        :type force_refresh: bool
        """
        try:
            self._secrets = self._get_secrets_from_bws()
            self._last_cache_refresh = time.time()
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to refresh secrets cache due to subprocess error: {e}")
            if force_refresh or not self._secrets:
                raise
        except ValueError as e:
            logger.error(f"Failed to refresh secrets cache due to value error: {e}")
            if force_refresh or not self._secrets:
                raise

    def refresh_secrets_cache(self, force_refresh: bool = False) -> None:
        """
        Refresh the secrets cache.

        :param force_refresh: Whether to force a refresh.
        :type force_refresh: bool
        """
        with self._lock:
            current_time = time.time()
            needs_refresh = force_refresh or (current_time - self._last_cache_refresh > self.cache_duration)
            if needs_refresh:
                self._attempt_cache_refresh(force_refresh)

    def call_and_return_text(
        self, cl_args: list, print_to_console: bool = False, as_json: bool = True
    ) -> str | dict | list:
        """
        Make a call to `bws` CLI. Be careful with this as it can break compatibility with the BWS class (e.g.
        deleting all secrets in a project or creating secrets with duplicate key names). See README.md for more
        information.

        :param cl_args: Args in list format (e.g. ['project', 'list']). Supply each word or option as a separate
                list item.
        :type cl_args: list
        :param print_to_console: Call print() on the stdout results. Defaults to False.
        :type print_to_console: bool
        :param as_json: Return the results converted to JSON. Defaults to True.
        :type as_json: bool
        :return: stdout
        :rtype: str | dict | list
        """
        return self._call_bws(cl_args=cl_args, print_to_console=print_to_console, as_json=as_json)

    def get_secret(self, key: str, value_only: bool = False) -> dict | str:
        """
        When accessing the BWS object like a dictionary, only the 'value' field for the given key is returned.

        :param key: Secret name.
        :type key: str
        :param value_only: Return only the secret's 'value' field instead of the whole dict.
        :type value_only: bool

        :return str | dict: Secret 'value' field or the full secret dict.

        # Example return value:
        {
            'id': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
            'organizationId': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
            'projectId': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
            'key': 'secret_1',
            'value': 'secret_1_value',
            'note': '',
            'creationDate': '2001-01-01T01:23:45.678901234Z',
            'revisionDate': '2001-01-01T01:23:45.678901234Z'
        }
        """
        return self._secrets[key]["value"] if value_only else self._secrets[key]

    def add_secret(self, key: str, value: str, print_to_console: bool = False) -> dict:
        """
        Add a new secret key/value pair. Adds to the internal cache without refreshing the whole thing.

        :param key: Key to add.
        :type key: str
        :param value: Secret value.
        :type value: str
        :param print_to_console: Call print() on the stdout results. Defaults to False.
        :type print_to_console: bool

        :return dict: Full new secret dict.
        :return type: dict

        :raises BWSKeyExists: If the key already exists in the project.
        """
        if key in self:
            raise BWSKeyExistsException(f"Key {key} already exists in the project. Did you mean to call update_secret_value()?")

        full_secret = self.call_and_return_text(
            cl_args=["secret", "create", key, value, self.project_id], print_to_console=print_to_console
        )
        logger.info(f'Added secret "{key}" to project "{self.project_name}"')
        self._secrets[key] = full_secret
        return full_secret

    def update_secret_value(self, key: str, value: str, print_to_console: bool = False) -> dict:
        """
        Update the value of a given secret. Updates internal cache without refreshing the whole thing.

        :param key: Key to update.
        :type key: str
        :param value: Replacement value.
        :type value: str
        :param print_to_console: Call print() on the stdout results. Defaults to False.
        :type print_to_console: bool

        :return dict: Full updated secret dict.
        :return type: dict

        :raises BWSKeyNotFound: If the provided key is invalid.
        """
        try:
            secret_id = self._secrets[key]["id"]
        except KeyError:
            raise BWSKeyNotFound(f"Key {key} not found in project {self.project_name}.")

        full_secret = self.call_and_return_text(
            cl_args=["secret", "edit", secret_id, "--value", value], print_to_console=print_to_console
        )
        logger.info(f'Updated value for secret "{key}" in project "{self.project_name}"')
        self._secrets[key] = full_secret
        return full_secret

    def delete_secret(self, key: str, print_to_console: bool = False) -> None:
        """
        Delete a secret. Updates internal cache without refreshing the whole thing.

        :param key: Key to delete.
        :type key: str
        :param print_to_console: Call print() on the stdout results. Defaults to False.
        :type print_to_console: bool

        :return: None

        :raises BWSKeyNotFound: If the provided key is invalid.
        """
        try:
            secret_id = self._secrets[key]["id"]
        except KeyError:
            raise BWSKeyNotFound(f"Key {key} not found in project {self.project_name}.")

        self.call_and_return_text(
            cl_args=["secret", "delete", secret_id], print_to_console=print_to_console, as_json=False
        )
        del self._secrets[key]
        logger.info(f'Deleted secret "{key}" from project "{self.project_name}"')

    def items(self) -> list[tuple[str, dict]]:
        """
        Call .items() on the secrets cache.

        :return: List of tuples containing secret key and secret dict.
        """
        return list(self._secrets.items())

    def as_dict(self) -> dict[str, dict[str, str]]:
        """
        Returns a deepcopy of the internal secrets cache containing all project secrets.

        :return: Deepcopy of the internal secrets cache.
        """
        return deepcopy(self._secrets)

    def help(self, print_to_console: bool = True) -> str:
        """
        `bws` -h (help) command.

        :param print_to_console: Defaults to True.
        :type print_to_console: bool
        :return: Console output as string.
        :rtype: str
        """
        return self.call_and_return_text(cl_args=["-h"], print_to_console=print_to_console, as_json=False)

    def version(self, print_to_console=True) -> str:
        """
        `bws` -V (version) command.

        :param print_to_console: Defaults to True.
        :type print_to_console: bool
        :return: Console output as string.
        :rtype: str
        """
        return self.call_and_return_text(cl_args=["-V"], print_to_console=print_to_console, as_json=False)
