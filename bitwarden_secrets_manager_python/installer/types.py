from typing import Callable, Optional, TypeVar, Generator

ProgressCallback = Callable[[int, Optional[int]], None]
DT = TypeVar("DT", bytes, str, Generator[bytes, None, None], Generator[str, None, None])
