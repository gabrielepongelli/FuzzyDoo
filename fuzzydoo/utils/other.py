import os
import sys
import shutil
from contextlib import contextmanager
from typing import IO, Any, Iterable, NoReturn, TypeVar
from collections.abc import Callable, Generator


@contextmanager
def opened_w_error(*args, **kwargs) -> Generator[tuple[IO, None] | tuple[None, OSError], Any, None]:
    """Open a file with error handling.

    This function attempts to call the built-in open function with the arguments specified, and if 
    an error is raised it is inserted inside the context.

    The file is automatically closed in a finally block after the context manager is exited.

    Args:
        args: Positional arguments that will be passed to the built-in open function.
        kwargs: Keyword arguments to pass to the built-in open function.

    Yields:
        A tuple which can be in one of the following combinations:
        1. The first element is the opened file object, and the second element is `None`.
        2. The first element is `None`, and the second element is the `OSError` instance raised by 
            the built-in open function.
    """
    try:
        # pylint: disable=unspecified-encoding
        f: IO = open(*args, **kwargs)
    except OSError as e:
        yield None, e
    else:
        try:
            yield f, None
        finally:
            f.close()


T = TypeVar('T')


def first_true(
        iterable: Iterable[T],
        default: Any = False,
        pred: Callable[[T], bool] = None) -> T | Any:
    "Returns the first true value or the *default* if there is no true value."

    return next(filter(pred, iterable), default)


def run_as_root() -> NoReturn:
    """Run the current process as root."""

    sudo = shutil.which('sudo')
    os.execv(sudo, [sudo, sys.executable] + sys.argv)
