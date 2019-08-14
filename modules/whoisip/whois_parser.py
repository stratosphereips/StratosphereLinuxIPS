import ipaddress


class Response:
    def __init__(self, ip, cidr=None, asn=None):
        self.ip = ip
        self.cidr = cidr
        self.asn = asn
        self.data = []
        self.modified = None
        self.country = None
        self.name = None
        self.cidr_prefixlen = 0
        self.num_missing_values = 0
        self.important_fields = {"asn": None, "country": None, "cidr": None, "route": None, "netrange": None,
                                 "inetnum": None, "name": None, "orgname": None, "netname": None, "org-name": None,
                                 "last-modified": None}

    def add_value(self, line):
        """
        Save a line of data (in a "key:     value" format) to the Response object
        :param line: one line of the input
        :return: None
        """
        key, value = line.split(": ", 1)
        key = key.lower()
        value = value.strip()

        # remove comments from lines with country codes. Codes always have two letters.
        if key == "country":
            value = value[0:2]

        # TODO: It seems like the self.data field is not needed, maybe remove it
        # if key was already read, append to it
        # if key in self.data:
        #     self.data[key] = self.data[key] + "\n" + value
        # if the key was not seen before, add it
        # else:
        #     self.data[key] = value

        # save important keys separately, this will make processing easier
        if key in self.important_fields and self.important_fields[key] is None:
            self.important_fields[key] = value

    def process(self):
        """
        Read data from the response and choose the correct values. Also, compute the statistics to evaluate the response
        :return: None
        """

        if self.asn is None:
            self.asn = self.important_fields["asn"]

        if self.cidr is None:
            if self.important_fields["cidr"] is not None:
                self.cidr = self.important_fields["cidr"]
            elif self.important_fields["route"] is not None:
                self.cidr = self.important_fields["route"]
            elif self.important_fields["netrange"] is not None:
                self.cidr = get_cidr_from_net_range(self.important_fields["netrange"])
            elif self.important_fields["inetnum"] is not None:
                self.cidr = get_cidr_from_net_range(self.important_fields["inetnum"])

        self.country = self.important_fields["country"]

        if self.important_fields["name"] is not None:
            self.name = self.important_fields["name"]
        elif self.important_fields["orgname"] is not None:
            self.name = self.important_fields["orgname"]
        elif self.important_fields["org-name"] is not None:
            self.name = self.important_fields["org-name"]
        elif self.important_fields["netname"] is not None:
            self.name = self.important_fields["netname"]

        # update which variables are missing, compute length of the mask prefix
        if self.asn is None:
            self.num_missing_values += 1

        if self.cidr is None:
            self.num_missing_values += 1
            # if no cidr is present, set prefix to zero. This way, it will be the least preferable network
            self.cidr_prefixlen = 0
        else:
            # there may be more networks on one line, choose the smallest one
            smallest_prefix = 0
            smallest_network = "0.0.0.0/32"
            networks = self.cidr.split(", ")
            for network in networks:
                if self.ip not in ipaddress.IPv4Network(network):
                    networks.remove(network)
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


def get_data_from_query(ip, query, asn, ctr_code, cidr, name):
    # get a set of responses
    server_response, subnet_responses = parse_raw_query(ip, query)

    all_set = False
    for response in subnet_responses:
        asn, ctr_code, cidr, name, all_set = update_missing_fields(response, asn, ctr_code, cidr, name)
        if all_set:
            break

    if server_response is not None and not all_set:
        asn, ctr_code, cidr, name, _ = update_missing_fields(server_response, asn, ctr_code, cidr, name)

    result = {}

    # if IP isn't registered, the mask of an empty network is returned (eg IP 194.31.224.157)
    # Description of the query: This object represents all IPv4 addresses. If you see this object as a result of a
    # single IP query, it means that the IP address you are querying is currently not assigned to any organisation
    if cidr == "0.0.0.0/32":
        result["cidr"] = None
        result["asn"] = None
        result["country"] = None
        result["name"] = None
    else:
        result["cidr"] = str(cidr)
        result["asn"] = str(asn)
        result["country"] = str(ctr_code)
        result["name"] = str(name)

    return result


def update_missing_fields(response, asn, country, cidr, name):
    all_set = True
    if asn is None:
        if response.asn is not None:
            asn = response.asn
        else:
            all_set = False
    if country is None:
        if response.country is not None:
            country = response.country
        else:
            all_set = False
    if cidr is None:
        if response.cidr is not None:
            cidr = response.cidr
        else:
            all_set = False
    if name is None:
        if response.name is not None:
            name = response.name
        else:
            all_set = False
    return asn, country, cidr, name, all_set


def parse_raw_query(ip, query):
    responses = []

    for line in query.split("\n"):
        # remove comments
        if line.startswith("#"):
            # start a new response section when '# start' is read
            if "start" in line:
                responses.append(Response(ip))
            continue
        # remove comments
        if line.startswith("%"):
            if line.startswith("% Information related to"):
                # start a new response section when '% Information related to ...' is read
                responses.append(Response(ip))
                # the header contains cidr and (sometimes) asn data
                cidr, asn = get_cidr_from_whois_header(line)
                responses[-1].cidr = cidr
                responses[-1].asn = asn
            continue
        # remove empty lines
        if line == "":
            continue
        # ignore lines that don't follow the 'key: value' format
        if ": " not in line:
            continue

        # if no responses are already in the array, start a new response
        if len(responses) == 0:
            responses.append(Response(ip))

        responses[-1].add_value(line)

    for response in responses:
        response.process()

    # sometimes, whois server first responds with information about itself. The server data should not be interpreted
    # as data for IP, as the company name and country (and other stuff) may be different
    if len(responses) > 1:
        server_response = responses[0]
        subnet_responses = responses[1:]
        subnet_responses.sort()
        return server_response, subnet_responses

    else:
        return None, responses


def get_cidr_from_whois_header(line: str):
    line = line[25:]
    # range of ips
    if "-" in line:
        line = line.replace("\'", "")
        return get_cidr_from_net_range(line), None
    if "AS" in line:
        line = line.replace("\'", "")
        cidr, asn = line.split("AS")
        return cidr, asn


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
