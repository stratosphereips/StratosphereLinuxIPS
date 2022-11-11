from modules.p2ptrust.trust.trustdb import TrustDB
from modules.p2ptrust.utils.printer import Printer


class Model:
    """
    Abstract model for computing reputations of peers and IP addresses

    This class defines a method that trust model is expected to have.
    """

    def __init__(
        self,
        printer: Printer,
        trustdb: TrustDB,
    ):
        self.printer = printer
        self.trustdb = trustdb


    def get_opinion_on_ip(self, ipaddr: str) -> (float, float, float):
        """
        Compute the network's opinion for a given IP

        :param ipaddr: The IP address for which the opinion is computed
        :return: peer's reputation, score and confidence
        """
        raise NotImplementedError()
