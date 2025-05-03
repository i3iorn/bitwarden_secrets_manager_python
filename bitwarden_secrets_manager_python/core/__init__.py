#!/usr/bin/env python3
"""
Secure, modular Bitwarden CLI wrapper with retry, context management, and extension hooks.
"""
import json
import logging
import os
import shlex
import subprocess
import shutil
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from bitwarden_secrets_manager_python.core.runner import Runner, DefaultRunner
from bitwarden_secrets_manager_python.core.utils import redact, CommandError, BWObjects
from bitwarden_secrets_manager_python.utils import retry

logger = logging.getLogger(__name__)


class BitwardenCLI:
    """
    Core wrapper for Bitwarden CLI.
    Supports global options, retries, and hooks.
    Provides a simple interface for executing commands and handling responses.

    Properties:
        - bws_path: Path to the Bitwarden CLI executable.
        - global_opts: Global options for the CLI.
        - secrets: List of sensitive data to redact from logs.
        - runner: Command runner for executing CLI commands.
        - timeout: Timeout for command execution.
        - hooks: Dictionary of pre and post execution hooks.

    Methods:
        - register_hook(phase: str, fn: Callable[..., None]) -> None: Register a hook for pre or post
    """
    def __init__(
        self,
        executable: Optional[str] = None,
        access_token: Optional[str] = None,
        runner: Runner = DefaultRunner(),
        timeout: float = 30.0,
    ):
        self.runner = runner
        self.timeout = timeout
        self.lock = threading.Lock()
        self.hooks: Dict[str, List[Callable[..., None]]] = {"pre": [], "post": []}

        exe = executable or os.getenv("BWS_PATH", "bws.exe")
        path = shutil.which(exe) or exe
        self.bws_path = Path(path)
        if not shutil.which(str(self.bws_path)):
            raise FileNotFoundError(f"Bitwarden CLI not found at {self.bws_path}")
        logger.debug(f"Resolved CLI path: {self.bws_path}")

        token = access_token or os.getenv("BWS_ACCESS_TOKEN", "")
        if token and len(token) < 20:
            raise ValueError("Access token length suspiciously short")
        self.secrets = [token]
        self.global_opts = ["--access-token", token] if token else []

    def register_hook(self, phase: str, fn: Callable[..., None]) -> None:
        if phase not in self.hooks:
            raise ValueError(f"Unknown hook phase: {phase}")
        self.hooks[phase].append(fn)

    def _run_hooks(self, phase: str, args: List[str]) -> None:
        for fn in self.hooks.get(phase, []):
            try:
                fn(args)
            except Exception as e:
                logger.debug(f"Hook error in {phase}: {e}")

    def _build_cmd(self, args: List[str]) -> List[str]:
        args = [arg.value if isinstance(arg, BWObjects) else arg for arg in args if arg is not None]
        return [str(self.bws_path), *args, *self.global_opts]

    def execute_text(self, args: List[str], input_data: Optional[str] = None) -> str:
        return self.execute(args, parse_json=False, input_data=input_data)

    def execute_json(self, args: List[str], input_data: Optional[str] = None) -> Any:
        return self.execute(args, parse_json=True, input_data=input_data)

    @retry(retries=3)
    def execute(
        self,
        args: List[Union[BWObjects, str]],
        parse_json: bool = True,
        input_data: Optional[str] = None,
    ) -> Any:
        cmd = self._build_cmd(args)
        safe = redact(shlex.join(cmd), self.secrets)
        logger.debug(f"Executing: {safe}")

        self._run_hooks("pre", cmd)
        with self.lock:
            try:
                cp = self.runner.run(
                    cmd,
                    timeout=self.timeout,
                    input=input_data,
                )
            except subprocess.CalledProcessError as e:
                raise CommandError(cmd, e.returncode, e.stdout or "", e.stderr or "")
            except subprocess.TimeoutExpired as e:
                raise CommandError(cmd, -1, e.stdout or "", e.stderr or "")
        self._run_hooks("post", cmd)

        out = cp.stdout.strip()
        if parse_json:
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON: {out}")
                raise
        return out

    def version(self) -> Optional[str]:
        try:
            return self.execute(["--version"], parse_json=False)
        except Exception:
            return None
