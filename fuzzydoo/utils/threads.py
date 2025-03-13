import threading
import asyncio
from dataclasses import fields
from typing import override, TypeVar


class EventStoppableThread(threading.Thread):
    """A thread class that can be gracefully stopped using an event mechanism.

    This class extends the standard `threading.Thread` class by incorporating a `stop_event`
    attribute. This event can be used to signal the thread to stop its execution in a controlled 
    manner, allowing for more graceful termination of long-running or looping threads.

    Usage:
        Subclass `EventStoppableThread` and implement the `run` method. Within the `run` method,
        periodically check the `stop_event` (e.g., `if self.stop_event.is_set(): break`) to 
        determine if the thread should terminate. To stop the thread externally, call the `join` 
        method, which will set the stop event and wait for the thread to finish.

    Example:
        >>> class MyThread(EventStoppableThread):
        >>>     def run(self):
        >>>         while not self.stop_event.is_set():
        >>>             # Perform some work
        >>>             time.sleep(1)
        >>> 
        >>> thread = MyThread()
        >>> thread.start()
        >>> # ... do some work ...
        >>> thread.join()  # This will stop the thread gracefully
    """

    stop_event: threading.Event
    """An event object that, when set, signals the thread to stop."""

    def __init__(self):
        """Initializes an instance of `EventStoppableThread`.

        This constructor sets up the thread with a stop event that can be used
        to signal the thread to stop its execution gracefully.
        """

        super().__init__()

        self.stop_event = threading.Event()
        self.stop_event.clear()

    @override
    def join(self, timeout=None):
        """Signals the thread to stop and waits for it to terminate."""

        self.stop_event.set()
        super().join(timeout)


class ExceptionRaiserThread(threading.Thread):
    """A thread class that provides a mechanism for handling exceptions raised during execution.

    This class extends the standard `threading.Thread` class by adding functionality to capture
    and store exceptions that occur during the thread's execution. It allows for more graceful
    error handling and provides a way to check if an error occurred and retrieve the exception.

    Usage:
        Subclass `ExceptionRaiserThread` and implement the `handled_run` method. After starting
        the thread, you can check `is_error_occurred` to see if an exception was raised, and
        access the `exception` attribute to retrieve the exception object if one occurred.

    Example:
        >>> class MyThread(ExceptionRaiserThread):
        >>>     def handled_run(self):
        >>>         # Simulating some work that might raise an exception
        >>>         if some_condition:
        >>>             self.is_error_recoverable = False
        >>>             raise ValueError("An error occurred")
        >>>         # Perform other operations
        >>>
        >>> thread = MyThread()
        >>> thread.start()
        >>> thread.join()
        >>> 
        >>> if thread.is_error_occurred:
        >>>     print(f"An error occurred: {thread.exception}")
        >>>     if thread.is_error_recoverable:
        >>>         # Implement recovery logic
        >>>     else:
        >>>         # Handle unrecoverable error
        >>> else:
        >>>     print("Thread completed successfully")
    """

    exception: Exception | None
    """Exception that occurs during thread execution, or `None` if no exception is raised."""

    is_error_recoverable: bool
    """Whether an error that occurred is recoverable or not."""

    def __init__(self):
        """Initialize an `ExceptionRaiserThread` instance."""

        super().__init__()

        self.exception = None
        self.is_error_recoverable = True

    @property
    def is_error_occurred(self) -> bool:
        """Whether an error has occurred or not."""

        return self.exception is not None

    def handled_run(self):
        """Run code in the thread and handle raised exceptions."""

        return

    @override
    def run(self):
        try:
            self.handled_run()
        except Exception as e:
            self.exception = e


DataclassT = TypeVar('DataclassT')


def with_thread_safe_get_set(cls: DataclassT) -> DataclassT:
    """Class decorator that secures each attribute access of `cls` with a lock.

    This decorator creates a new lock for each attribute of `cls` and reimplements the 
    `__getattribute__` and `__setattr__` methods to use these locks, ensuring thread-safe 
    access to the attributes.

    Args:
        cls: The class to be decorated, which should be a dataclass.

    Returns:
        DataclassT: The decorated class with thread-safe attribute access.
    """

    original_init = cls.__init__

    def new_init(self, *args, **kwargs):
        object.__setattr__(
            self, '_locks', {f.name: threading.Lock() for f in fields(cls)})
        original_init(self, *args, **kwargs)

    cls.__init__ = new_init

    def new_setattr(self, name, value):
        # pylint: disable=protected-access
        if name in self._locks:
            with self._locks[name]:
                super(cls, self).__setattr__(name, value)
        else:
            super(cls, self).__setattr__(name, value)

    cls.__setattr__ = new_setattr

    def new_getattr(self, name):
        _locks = super(cls, self).__getattribute__('_locks')
        if name in _locks:
            with _locks[name]:
                return super(cls, self).__getattribute__(name)
        else:
            return super(cls, self).__getattribute__(name)

    cls.__getattribute__ = new_getattr

    return cls


class AsyncioThreadSafeEvent(asyncio.Event):
    """A thread-safe version of `asyncio.Event` for use across different threads.

    This class extends the standard `asyncio.Event` to provide thread-safe `set` and `clear`
    operations. It ensures that these operations are executed in a thread-safe manner by using
    the `call_soon_threadsafe` method of the event loop.

    Note:
        While `set` and `clear` are thread-safe, other methods inherited from `asyncio.Event`
        (like `wait`) should still be called from within the event loop's thread.

    Example:
        >>> import asyncio
        >>> import threading
        >>> 
        >>> event = AsyncioThreadSafeEvent()
        >>> 
        >>> async def waiter():
        ...     print("Waiting for event...")
        ...     await event.wait()
        ...     print("Event set!")
        >>> 
        >>> def setter():
        ...     print("Setting event from another thread")
        ...     event.set()
        >>> 
        >>> async def main():
        ...     loop = asyncio.get_running_loop()
        ...     wait_task = loop.create_task(waiter())
        ...     threading.Thread(target=setter).start()
        ...     await wait_task
        >>> 
        >>> asyncio.run(main())
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._loop = asyncio.get_event_loop()

    def set(self):
        self._loop.call_soon_threadsafe(super().set)

    def clear(self):
        self._loop.call_soon_threadsafe(super().clear)


__all__ = [
    'EventStoppableThread',
    'ExceptionRaiserThread',
    'with_thread_safe_get_set',
    'AsyncioThreadSafeEvent'
]
