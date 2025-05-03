import subprocess
from typing import Protocol, List, Any, Optional


class Runner(Protocol):
    def run(
        self,
        cmd: List[str],
        **kwargs: Any
    ) -> subprocess.CompletedProcess:
        ...


class DefaultRunner:
    """Default subprocess runner using subprocess.run"""
    def run(
        self,
        cmd: List[str],
        capture_output: bool = True,
        text: bool = True,
        check: bool = True,
        timeout: Optional[float] = None,
        input: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=capture_output,
            text=text,
            check=check,
            timeout=timeout,
            input=input,
        )
