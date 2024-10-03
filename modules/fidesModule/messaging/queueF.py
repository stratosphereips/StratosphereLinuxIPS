from threading import Thread
from typing import Callable, Optional

from redis.client import Redis

from ..messaging.queue import Queue
from ..utils.logger import Logger

logger = Logger(__name__)


class RedisQueue(Queue):
    """Implementation of Queue interface that uses two Redis queues."""

    def listen(self,
               on_message: Callable[[str], None],
               block: bool = False,
               sleep_time_in_new_thread: float = 0.001,
               **argv
               ):
        """Starts listening, if :param: block = True, the method blocks current thread!"""
        raise NotImplemented('Use implementation and not interface!')

    def get_message(self, timeout_seconds: float = 0) -> Optional[dict]:
        """Get the next message if one is available, otherwise None.

        Note that this method returns directly message coming from the Redis, no parsing is done.

        If timeout is specified, the system will wait for `timeout` seconds
        before returning. Timeout should be specified as a floating point
        number.
        """
        raise NotImplemented('Use implementation and not interface!')


class RedisSimplexQueue(Queue):
    """
    Implementation of Queue interface that uses two Redis queues.
    One for sending data and one for listening.
    """

    def __init__(self, r: Redis, send_channel: str, received_channel: str):
        self.__r = r
        self.__receive = received_channel
        self.__send = send_channel
        self.__pub = self.__r.pubsub()
        self.__pub_sub_thread: Optional[Thread] = None

    def send(self, serialized_data: str, **argv):
        self.__r.publish(self.__send, serialized_data)

    def listen(self,
               on_message: Callable[[str], None],
               block: bool = False,
               sleep_time_in_new_thread: float = 0.001,
               **argv
               ):
        """Starts listening, if :param: block = True, the method blocks current thread!"""
        if block:
            return self.__listen_blocking(on_message)
        else:
            return self.__register_handler(on_message, sleep_time_in_new_thread)

    def __register_handler(self,
                           on_message: Callable[[str], None],
                           sleep_time_in_new_thread: float) -> Thread:
        # subscribe with given
        self.__pub.subscribe(**{self.__receive: lambda x: self.__exec_message(x, on_message)})
        self.__pub_sub_thread = self.__pub.run_in_thread(sleep_time=sleep_time_in_new_thread)

        return self.__pub_sub_thread

    def __listen_blocking(self, on_message: Callable[[str], None]):
        if not self.__pub.subscribed:
            self.__pub.subscribe(self.__receive)

        for msg in self.__pub.listen():
            self.__exec_message(msg, on_message)

    def __exec_message(self, redis_msg: dict, on_message: Callable[[str], None]):
        data = None
        if redis_msg is not None \
                and redis_msg['data'] is not None \
                and type(redis_msg['data']) == str:
            data = redis_msg['data']

        if data is None:
            return
        elif data == 'stop_process':
            logger.debug(f'Stop process message received! Stopping subscription.')
            # unsubscribe from the receive queue
            self.__pub.unsubscribe(self.__receive)
            self.__pub.close()
            # and stop thread if it is possible
            try:
                if hasattr(self.__pub_sub_thread, 'stop'):
                    self.__pub_sub_thread.stop()
            except Exception as ex:
                logger.debug(f'Error when stopping thread: {ex}')
            return
        logger.debug(f'New message received! {data}')

        try:
            on_message(data)
        except Exception as ex:
            logger.error(f'Error when executing on_message!, {ex}')

    def get_message(self, timeout_seconds: float = 0) -> Optional[dict]:
        """Get the next message if one is available, otherwise None.

        Note that this method returns directly message coming from the Redis,
        the data that were sent ar

        If timeout is specified, the system will wait for `timeout` seconds
        before returning. Timeout should be specified as a floating point
        number.
        """
        if not self.__pub.subscribed:
            self.__pub.subscribe(self.__receive)

        return self.__pub.get_message(timeout=timeout_seconds)


class RedisDuplexQueue(RedisSimplexQueue):
    """
    Implementation of Queue interface that uses single Redis queue
    for duplex communication (sending and listening on the same channel).
    """

    def __init__(self, r: Redis, channel: str):
        super().__init__(r, channel, channel)
