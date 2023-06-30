from modules.p2ptrust.trust.trustdb import TrustDB


class Model:
    """
    Abstract model for computing reputations of peers and IP addresses

    This class defines a method that trust model is expected to have.
    """
    name = 'P2P Model'
    def __init__(
        self,
        output_queue,
        trustdb: TrustDB,

    ):
        self.output_queue = output_queue
        self.trustdb = trustdb

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.output_queue.put(f'{levels}|{self.name}|{text}')


    def get_opinion_on_ip(self, ipaddr: str) -> (float, float, float):
        """
        Compute the network's opinion for a given IP

        :param ipaddr: The IP address for which the opinion is computed
        :return: peer's reputation, score and confidence
        """
        raise NotImplementedError()
