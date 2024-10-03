from typing import Callable


class Queue:
    """
    Wrapper around actual implementation of queue.

    Central point used for communication with the network layer and another peers.
    """

    def send(self, serialized_data: str, **argv):
        """Sends serialized data to the queue."""
        raise NotImplemented('This is interface. Use implementation.')

    def listen(self, on_message: Callable[[str], None], **argv):
        """Starts listening, executes :param: on_message when new message arrives.

        Depending on the implementation, this method might be blocking.
        """
        raise NotImplemented('This is interface. Use implementation.')
