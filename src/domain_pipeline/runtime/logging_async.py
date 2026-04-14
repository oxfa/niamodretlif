"""Queue-based logging transport for the async runtime."""

from __future__ import annotations

import logging
from logging.handlers import QueueHandler, QueueListener
from queue import SimpleQueue


class RuntimeLogTransport:
    """QueueHandler/QueueListener pair for async worker logging."""

    def __init__(self) -> None:
        self.queue: SimpleQueue[logging.LogRecord] = SimpleQueue()
        self.handler = QueueHandler(self.queue)
        self.listener: QueueListener | None = None
        self._original_handlers: tuple[logging.Handler, ...] = ()

    def install(self) -> None:
        """Route root-logger records through the queue listener once."""
        root_logger = logging.getLogger()
        self._original_handlers = tuple(root_logger.handlers)
        self.listener = QueueListener(
            self.queue,
            *self._original_handlers,
            respect_handler_level=True,
        )
        for current_handler in self._original_handlers:
            root_logger.removeHandler(current_handler)
        root_logger.addHandler(self.handler)
        self.listener.start()

    def uninstall(self) -> None:
        """Stop queue routing and restore the original root handlers."""
        root_logger = logging.getLogger()
        root_logger.removeHandler(self.handler)
        if self.listener is not None:
            self.listener.stop()
            self.listener = None
        for current_handler in self._original_handlers:
            root_logger.addHandler(current_handler)
        self._original_handlers = ()
