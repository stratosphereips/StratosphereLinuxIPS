import ipaddress
from dateutil import parser


class Response:
    """
    Response is a section of the full query, which is given by one server and contains information about one network.
    There may be more types in the response, the tracked types are inetnum, organization, role and their alternatives
    when the communicating server uses a different standard. Other types, such as maintainer and poem (!) are not needed
    in this use case and are ignored.
    For each type, a data dictionary is built from individual lines in the query (add_value_to_type). When all lines are
    read, the dictionaries are processed and fields in the response are set (if present in the data).
    """
    def __init__(self, ip):
        """
        Initialize a response
        :param ip: The IP address this response corresponds with
        """
        self.ip = ip
        self.cidr = None
        self.asn = None
        self.updated = None
        self.country = None
        self.name = None
        self.orgid = None
        self.cidr_prefixlen = 0
        # missing values are counted, and this is used as a secondary sorting criterion (first is network size)
        self.num_missing_values = 0

        # data dictionary for the inetnum/netrange type
        self.network = {}
        # data dictionary for the organization type
        self.organization = {}
        # data dictionary for the role type (role is sometimes used instead of organization)
        self.role = {}

        # a translation table to port key names from other servers to the RIPE standard
        self.key_translation = {"inetnum": "inetnum", "inet6num": "inetnum", "netrange": "inetnum",
                                "updated": "updated", "last-modified": "updated",
                                "org-name": "organization", "orgname": "organization", "organization": "organization",
                                "organisation": "organization", "role": "role"}
        # type names that should be processed (ignored types are not listed here)
        self.processed_types = ["inetnum", "inet6num", "netrange", "organization", "orgname", "role"]
        # a list to dynamically insert values to all types
        self.type_dictionaries = {"inetnum": self.network, "organization": self.organization, "role": self.role}
        # TODO: The whois authority that gave this response
        self.rir_server = ""

        if ip.version == 4:
            self.IPNetwork = ipaddress.IPv4Network
        else:
            self.IPNetwork = ipaddress.IPv6Network

    def add_value_to_type(self, line, object_type):
        """
        Save a line of data (in a "key:     value" format) to the Response object. This function also takes in the type
        of the current object (sets it if new object is read), and decides whether data in this type should be used.
        :param object_type: Object type of the currently parsed object. Empty string if first line of new type is read
        :param line: one line of the input
        :return: type: the current type (string). If object type is given, it is not changed. If empty string is given,
        the new object type is returned.
        """

        # if type is set and it is not something to be processed, do nothing
        if object_type != "" and object_type not in self.processed_types:
            return object_type

        # if type is known and processed, or if type is not known yet, process the line to get key
        key, value = line.split(": ", 1)
        key = key.lower().strip()
        value = value.strip()

        # some keys have different names on different servers, translate them
        if key in self.key_translation.keys():
            key = self.key_translation[key]

        # if type is not set (we are reading the first line of a new type), the key is set as name of the new type
        if object_type == "":
            object_type = key
            # if the new type is not to be processed, it is returned but not processed
            if object_type not in self.processed_types:
                return object_type

        # at this point, object_type is the correct type that should be processed, and key-value is the pair to save

        # remove comments from lines with country codes. Codes always have two letters.
        if key == "country":
            value = value[0:2]

        # sometimes a field is mentioned, but there is no value. Skip those empty lines
        if len(value) == 0:
            return object_type

        # save value into dictionary for the correct object
        self.type_dictionaries[object_type][key] = value

        return object_type

    def process(self):
        """
        Read data from the response and choose the correct values. Also, compute the missing_values so objects can be
        sorted later.
        The schema to read data is as follows:
        
        Every successful query will have at least one section (=response), and in each response, there is the
        NetRange/inetnum/inet6num type. In each response, 
         - The country code is read from the network
         - The organization name is read from the network. This is in the format "org-name (org-id)", and the two values
         are parsed and saved separately.
         - The ASN is read from the network
         - The last update time is read from the network
         If Organization info is included in the response:
         - The country code is taken from organization, but only if it was not set in the network
         - The update date of the organization is ignored, it is not relevant to the IP properties
         If Role is set instead of Organization:
         - The name is taken from Role
         If Organization and Role aren't set:
         - There may be no name property. In this case netname is used as "name"
        :return: None
        """

        # if CIDR is given, use it. Otherwise parse it from netrange/inetnum
        # TODO: handle IPv6
        if "cidr" in self.network:
            self.cidr = self.network["cidr"]
        elif "inetnum" in self.network:
            self.cidr = get_cidr_from_net_range(self.network["inetnum"])

        # update time
        if "updated" in self.network:
            self.updated = get_update_time(self.network["updated"])

        # country code
        if "country" in self.network:
            self.country = self.network["country"]
        elif "country" in self.organization:
            self.country = self.organization["country"]

        # name and orgid
        if "organization" in self.network:
            self.name, self.orgid = get_company_name_and_shortcut(self.network["organization"])
        if self.name is None:
            if "organization" in self.organization:
                self.name = self.organization["organization"]
            elif "netname" in self.network:
                self.name = self.network["netname"]
        if self.orgid is None and "orgid" in self.organization:
            self.orgid = self.organization["orgid"]

        # ASN
        if "originas" in self.network:
            self.asn = self.network["originas"]

        # check how many fields are set from this response, and how big the network is
        if self.cidr is None:
            self.num_missing_values += 1
            # if no cidr is present, set prefix to zero. This way, it will be the least preferable network
            self.cidr_prefixlen = 0
        else:
            # if cidr is set, there may be more networks on one line, choose the smallest one
            smallest_prefix = 0
            smallest_network = "0.0.0.0/32"
            networks = self.cidr.split(", ")
            for network in networks:
                if self.ip not in self.IPNetwork(network):
                    networks.remove(network)
                    continue
                prefix = int(network.split("/")[1])
                if prefix > smallest_prefix:
                    smallest_prefix = prefix
                    smallest_network = network
            self.cidr_prefixlen = smallest_prefix
            self.cidr = smallest_network

        if self.country is None:
            self.num_missing_values += 1

        if self.name is None:
            self.num_missing_values += 1

    def __lt__(self, other):
        """
        Compare two responses. The criteria used is:
         - if one network is smaller, it is better
         - if the sizes match and one response is more informed, it is better
         - if sizes and missing values match, the smaller asn is returned
        :param other: Response to compare to
        :return: True if self is better than other, False otherwise
        """
        # responses for smaller subnets (higher prefixlen) are preferred
        if self.cidr_prefixlen > other.cidr_prefixlen:
            return True
        elif self.cidr_prefixlen < other.cidr_prefixlen:
            return False

        # in case of same prefixlen, more informative responses are preferred
        if self.num_missing_values < other.num_missing_values:
            return True
        elif self.num_missing_values > other.num_missing_values:
            return False

        # in case of same prefixlen and missing values, choose the one with lower asn
        if self.asn is not None and other.asn is not None:
            if self.asn < other.asn:
                return True
            elif self.asn > other.asn:
                return False

        return False


def parse_raw_query(ip, query):
    """
    Read the query string and separate it into multiple responses. The responses are retuned in a list.
    
    The whois response is based on keys and values that are separated by ":". Each new pair is separated by a newline,
    although sometimes the value is split to multiple new lines and in that case, it won't be correctly parsed. The
    values needed in SLIPS are short and never spread to more lines. There is no international standard, so the names
    for the same value may differ.
    
    Some lines start with commenting characters (# or %), and these lines contain either useless information about the
    server, or they separate Responses. Namely, the separators of Responses are the "# start" and "# end" tags, or the
    longer phrase "% Information related to ..."
    
    Each Response is separated into objects by double newlines. Each object can have different "type", depending on what
    the object is describing. The type is actually the key on the first line of the object. There is one inetnum object
    in every Response, and it describes what network the IP belongs to. Apart from inetnum, there is also
    "organization", who owns the IP (likely) and a maintainer, abuseInfo etc. Only some types are significant to SLIPS,
    and they are filtered by the Response object
    
    To parse the input, an array of responses is prepared. With each separation comment, a new response is appended to
    the end of the array. With newlines, the type is reset, and it is set again to the first read key. When reading
    regular key:value lines, they are added with the most recent type to the most recent Response.
    
    :param ip: ip address
    :param query: string coming from the whois command
    :return: server Response and list of sorted Responses. If there is only one Response, it is left in the list and
    server_response=None is returned.
    """
    responses = []
    last_type = ""

    for line in query.split("\n"):
        # ignore comments
        if line.startswith("#"):
            # start a new response section when '# start' is read
            if "start" in line:
                responses.append(Response(ip))
            continue
        # ignore comments
        if line.startswith("%"):
            if line.startswith("% Information related to"):
                # start a new response section when '% Information related to ...' is read
                responses.append(Response(ip))
                # the header contains cidr and (sometimes) asn data
                cidr, asn = get_cidr_from_whois_header(line)
                responses[-1].cidr = cidr
                responses[-1].asn = asn
            continue
        # start new type on empty line
        if line == "":
            # reset last type, because types are separated by empty lines
            last_type = ""
            continue
        # ignore lines that don't follow the 'key: value' format
        if ": " not in line:
            # TODO: make sure no relevant info is skipped (a regex to match line with url.*[-a-zA-Z0-9.]+\.[a-z]{2,}.*)
            continue

        # if no responses are already in the array, start a new response
        if len(responses) == 0:
            responses.append(Response(ip))

        # the line has some data, add it to the most recent Response
        last_type = responses[-1].add_value_to_type(line, last_type)

    # no new data will be read. Collect data inside the responses and prepare them for sorting
    for response in responses:
        response.process()

    # in case of more than one responses, separate the ARIN general response (it is always first) and sort the other
    # responses. The goal is that the smallest network and best results go first.
    if len(responses) > 1:
        server_response = responses[0]
        subnet_responses = responses[1:]
        subnet_responses.sort()
        return server_response, subnet_responses

    else:
        return None, responses


def get_cidr_from_whois_header(line: str):
    line = line[25:].upper()
    # range of ips
    if "-" in line:
        line = line.replace("\'", "")
        return get_cidr_from_net_range(line), None
    if "AS" in line:
        line = line.replace("\'", "")
        cidr, asn = line.split("AS")
        return cidr, asn
    # for ipv6, the cidr is given directly, but without asn ('\\'2001:718:2::/48\\'')
    return line.replace("\\", "").replace("\'", ""), None


def get_cidr_from_net_range(netrange):
    try:
        # get lower and higher IP strings from format 163.0.0.0 - 163.255.255.255
        min_address_str, max_address_str = netrange.split(" - ")
        # convert to IP address objects
        min_address = ipaddress.ip_address(min_address_str)
        max_address = ipaddress.ip_address(max_address_str)
        # only IPv4 addresses can be handled at the moment
        if min_address.version != 4:
            return None
        # subtract edge addresses to get size of network
        dif = int(max_address) - int(min_address)
        # use size to create IP, which will have all ones: 000.255.255.255
        inverted_mask = ipaddress.ip_address(dif)
        # from the lower IP and the inverted mask, ipaddress can parse the network cidr correctly
        network = str(ipaddress.IPv4Network(str(min_address) + "/" + str(inverted_mask)))
    except:
        network = None
    return network


def get_company_name_and_shortcut(organization):
    if "(" not in organization:
        return organization, None
    else:
        # split by the last occurrence of "("
        orgname, orgid = organization.rsplit("(", 1)
        orgname = orgname.strip()
        orgid = orgid.replace(")", "").strip()
        return orgname, orgid


def get_update_time(raw_data):
    return int(parser.parse(raw_data).timestamp())
