import asyncio
import logging
import time
import random
from functools import wraps
from inspect import iscoroutinefunction
from typing import Any, Callable, Optional, Type, Tuple, Union, TypeVar

T = TypeVar("T")
logger = logging.getLogger(__name__)

def retry(
    retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    jitter: Optional[float] = None,
    exceptions: Union[Type[BaseException], Tuple[Type[BaseException], ...]] = Exception,
    reraise: bool = True,
    return_exception: bool = False,
    log_context: Optional[str] = None,
    max_total_timeout: Optional[float] = None,
    retry_if: Optional[Callable[[BaseException], bool]] = None,
    on_retry: Optional[Callable[[int, BaseException], None]] = None,
    on_fail: Optional[Callable[[BaseException], None]] = None,
    backoff_func: Optional[Callable[[int, float], float]] = None,
    strict_return: bool = False,
) -> Callable[[Callable[..., T]], Callable[..., Union[T, None, BaseException]]]:
    """
    Decorator for retrying synchronous or asynchronous functions with exponential backoff.

    Supports:
    - sync and async functions
    - static and class methods
    - custom backoff logic
    - optional jitter
    - conditional retry
    - logging and hooks
    """
    def decorator(func: Callable[..., T]) -> Callable[..., Union[T, None, BaseException]]:

        def _get_wait(attempt: int, base: float) -> float:
            wait = backoff_func(attempt, base) if backoff_func else base * (backoff ** (attempt - 1))
            if jitter:
                wait += random.uniform(-jitter, jitter)
            return max(0.0, wait)

        async def _async_wrapper(*args: Any, **kwargs: Any) -> Union[T, None, BaseException]:
            start = time.monotonic()
            for attempt in range(1, retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    if retry_if and not retry_if(e):
                        raise
                    if attempt == retries:
                        _log_failure(func, e, attempt)
                        if on_fail:
                            on_fail(e)
                        return _handle_end(e)
                    _log_retry(func, e, attempt)
                    if on_retry:
                        on_retry(attempt, e)
                    wait = _get_wait(attempt, delay)
                    if max_total_timeout and (time.monotonic() - start) + wait > max_total_timeout:
                        _log_timeout(func, max_total_timeout)
                        return _handle_end(e)
                    await asyncio.sleep(wait)
            return None

        def _sync_wrapper(*args: Any, **kwargs: Any) -> Union[T, None, BaseException]:
            start = time.monotonic()
            for attempt in range(1, retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if retry_if and not retry_if(e):
                        raise
                    if attempt == retries:
                        _log_failure(func, e, attempt)
                        if on_fail:
                            on_fail(e)
                        return _handle_end(e)
                    _log_retry(func, e, attempt)
                    if on_retry:
                        on_retry(attempt, e)
                    wait = _get_wait(attempt, delay)
                    if max_total_timeout and (time.monotonic() - start) + wait > max_total_timeout:
                        _log_timeout(func, max_total_timeout)
                        return _handle_end(e)
                    time.sleep(wait)
            return None

        def _handle_end(exc: BaseException) -> Union[BaseException, None]:
            if reraise:
                raise exc
            return exc if return_exception else None

        def _log_retry(fn, e, attempt):
            name = log_context or fn.__name__
            logger.warning(f"{name} attempt {attempt} failed: {e}. Retrying…")
            logger.debug("Retry traceback:", exc_info=True)

        def _log_failure(fn, e, attempt):
            name = log_context or fn.__name__
            logger.error(f"{name} failed after {attempt} attempts: {e}")

        def _log_timeout(fn, timeout):
            name = log_context or fn.__name__
            logger.error(f"{name} exceeded total retry timeout of {timeout}s")

        # Handle static/class methods
        if isinstance(func, (staticmethod, classmethod)):
            inner_func = func.__func__
            wrapped = retry(
                retries=retries,
                delay=delay,
                backoff=backoff,
                jitter=jitter,
                exceptions=exceptions,
                reraise=reraise,
                return_exception=return_exception,
                log_context=log_context,
                max_total_timeout=max_total_timeout,
                retry_if=retry_if,
                on_retry=on_retry,
                on_fail=on_fail,
                backoff_func=backoff_func,
                strict_return=strict_return,
            )(inner_func)
            return type(func)(wrapped)

        wrapper = _async_wrapper if iscoroutinefunction(func) else _sync_wrapper
        return wraps(func)(wrapper)

    return decorator
