import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import TypeVar, List, Union, Callable, Any

logger = logging.getLogger(__name__)

SensitiveValue = TypeVar("SensitiveValue", bound=str)


class BWObjects(Enum):
    """Enum for Bitwarden CLI objects."""
    PROJECT = "project"
    ITEM = "item"
    COLLECTION = "collection"
    ORGANIZATION = "organization"
    SECRET = "secret"


def redact(text: str, secrets: List[str]) -> str:
    """Redact any occurrence of secrets in text for safe logging."""
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text


@dataclass
class CommandError(Exception):
    """Raised when an external command fails."""
    cmd: List[str]
    returncode: int
    stdout: str
    stderr: str

    def __str__(self) -> str:
        return (
            f"[BitwardenCLI Error] cmd={self.cmd} exit={self.returncode}\n"
            f"stdout={self.stdout or '<empty>'}\n"
            f"stderr={self.stderr or '<empty>'}"
        )


T = TypeVar("T")


