import threading
from typing import override


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


__all__ = ['EventStoppableThread']
