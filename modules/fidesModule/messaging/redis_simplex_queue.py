from threading import Thread
from typing import Callable, Optional


from slips_files.core.database.database_manager import DBManager
from ..messaging.queue import Queue
from ..utils.logger import Logger
from dataclasses import dataclass
from typing import List, Optional

logger = Logger(__name__)


class RedisSimplexQueue(Queue):
    """
    Implementation of Queue interface that uses two Redis queues.
    One for sending data and one for listening.
    """

    def __init__(
        self, db: DBManager, send_channel: str, received_channel: str, channels
    ):
        self.db = db
        self.__pub = channels[received_channel]
        self.__pub_sub_thread: Optional[Thread] = None
        self.__send = send_channel
        self.__receive = received_channel
        # to keep track of the threads opened by this class to be able to
        # close them later
        self._threads = []

    def send(self, serialized_data: str, **argv):
        self.db.publish(self.__send, serialized_data)

    def listen(
        self,
        on_message: Callable[[str], None],
        block: bool = False,
        sleep_time_in_new_thread: float = 0.001,
        **argv,
    ):
        """Starts listening, if :param: block = True,
        the method blocks current thread!"""
        if block:
            return self.__listen_blocking(on_message)
        else:
            return self.__register_handler(
                on_message, sleep_time_in_new_thread
            )

    def __register_handler(
        self,
        on_message: Callable[[str], None],
        sleep_time_in_new_thread: float,
    ) -> Thread:
        # subscribe with given
        self.__pub.subscribe(
            **{self.__receive: lambda x: self.__exec_message(x, on_message)}
        )
        # creates a new thread
        # this is simply a wrapper around `get_message()` that runs in a
        # separate thread
        self.__pub_sub_thread = self.__pub.run_in_thread(
            sleep_time=sleep_time_in_new_thread
        )
        self._threads.append(self.__pub_sub_thread)
        return self.__pub_sub_thread

    def __listen_blocking(self, on_message: Callable[[str], None]):
        ## subscription done in init
        # if not self.__pub.subscribed:
        #    self.__pub.subscribe(self.__receive)

        for msg in self.__pub.listen():
            self.__exec_message(msg, on_message)

    def __exec_message(
        self, redis_msg: dict, on_message: Callable[[str], None]
    ):
        data = None

        if (
            redis_msg is not None
            and redis_msg["data"] is not None
            and isinstance(redis_msg["data"], str)
        ):
            data = redis_msg["data"]

        if data is None:
            return

        elif data == "stop_process":
            logger.debug(
                "Stop process message received! " "Stopping subscription."
            )
            # unsubscribe from the receive queue
            self.__pub.unsubscribe(self.__receive)
            self.__pub.close()
            # and stop thread if it is possible
            try:
                if hasattr(self.__pub_sub_thread, "stop"):
                    self.__pub_sub_thread.stop()
            except Exception as ex:
                logger.debug(f"Error when stopping thread: {ex}")
            return
        logger.debug(f"New message received! {data}")

        try:
            on_message(data)
        except Exception as ex:
            logger.error(f"Error when executing on_message!, {ex}")

    def stop_all_queue_threads(self):
        """stops all tracked threads"""
        for thread in self._threads:
            if thread.is_alive():
                thread.stop()
        self._threads.clear()  # clear the thread list


class RedisDuplexQueue(RedisSimplexQueue):
    """
    Implementation of Queue interface that uses single Redis queue
    for duplex communication (sending and listening on the same channel).
    """

    def __init__(self, db: DBManager, channel: str, channels):
        super().__init__(db, channel, channel, channels)
