import threading
from typing import Callable, Optional

from ..messaging.queue import Queue
from ..utils.logger import Logger

logger = Logger(__name__)


class InMemoryQueue(Queue):
    """In Memory implementation of Queue.

    This should not be used in production.
    """

    def __init__(self, on_message: Optional[Callable[[str], None]] = None):
        def default_on_message(data: str):
            InMemoryQueue.__exception(data)

        self.__on_message: Callable[[str], None] = on_message if on_message else default_on_message

    def send(self, serialized_data: str, should_wait_for_join: bool = False, **argv):
        """Sends serialized data to the queue."""
        logger.debug('New data received for send.')
        if self.__on_message is None:
            self.__exception(serialized_data)

        th = threading.Thread(target=lambda: self.__on_message(serialized_data))
        th.start()
        if should_wait_for_join:
            th.join()

        return th

    def listen(self, on_message: Callable[[str], None], **argv):
        """Starts listening, executes :param: on_message when new message arrives.
        This method is not blocking.
        """
        self.__on_message = on_message

    @staticmethod
    def __exception(data: str):
        raise Exception(f'No on_message set! Call listen before calling send! Data: {data}')
