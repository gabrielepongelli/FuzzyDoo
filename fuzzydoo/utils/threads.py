import threading
from dataclasses import fields
from typing import override, TypeVar


class EventStoppableThread(threading.Thread):
    """Thread class that can be stopped by means of an event."""

    def __init__(self):
        threading.Thread.__init__(self)

        self.stop_event = threading.Event()
        self.stop_event.clear()

    @override
    def join(self, timeout=None):
        self.stop_event.set()
        super().join(timeout)


DataclassT = TypeVar('DataclassT')


def with_thread_safe_get_set(cls: DataclassT) -> DataclassT:
    """Class decorator that secure each attribute access of `cls` with a lock.

    This class creates a new lock for each attribute of `cls` and reimplements the 
    `__getattribute__` and `__setattr__` methods to use them.

    Args:
        cls: The class to be decorated.

    Returns:
        The decorated class with thread-safe attribute access.
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


__all__ = ['EventStoppableThread', 'with_thread_safe_get_set']
