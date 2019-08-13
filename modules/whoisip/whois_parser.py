import ipaddress


class Response:
    def __init__(self, cidr: str=None, asn: str=None):
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
        if key in self.data:
            self.data[key] = self.data[key] + "\n" + value
        # if the key was not seen before, add it
        else:
            self.data[key] = value

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
            self.cidr_prefixlen = int(self.cidr.split("/")[2])

        if self.country is None:
            self.num_missing_values += 1

        if self.name is None:
            self.num_missing_values += 1

    def __le__(self, other):
        # TODO: compare to other Responses. The smallest subnets should be used first (higher prefixes are preferred),
        # TODO: and in case of a match, the response with more fields should be used
        pass


def get_data_from_query(query, asn, ctr_code, cidr, name):
    # get a dictionary of values in the response
    data_dictionary = parse_raw_query(query)

    # TODO: sort the responses. Then, choose elements from the best responses. This will lead to combined results from
    # TODO: multiple responses, but this hopefuly doesn't matter
    result = {}

    # ASN
    # use original value if available
    if asn != "None":
        result["asn"] = asn
    # use manually read value if available
    elif "asn" in data_dictionary:
        result["asn"] = data_dictionary["asn"]
    # otherwise set "None"
    else:
        result["asn"] = "None"

    # Country
    # TODO: 163.194.132.190 is from US as far as cymruwhois says, but actually is in Australia. Who should I trust?
    if ctr_code != "None":
        result["country"] = ctr_code
        if "country" in data_dictionary and data_dictionary["country"] != ctr_code:
            print("### Warning: Country code from cymruwhois is", ctr_code, ", but whois returned", data_dictionary["country"])
    elif "country" in data_dictionary:
        result["country"] = data_dictionary["country"]
    else:
        result["country"] = "None"

    # CIDR
    if cidr != "None":
        result["cidr"] = cidr
    elif "cidr" in data_dictionary:
        result["cidr"] = data_dictionary["cidr"]
    # some servers use "route" instead of "cidr" for the key
    elif "route" in data_dictionary:
        result["cidr"] = data_dictionary["route"]
    # some servers provide network data in different format: 163.0.0.0 - 163.255.255.255
    elif "netrange" in data_dictionary:
        result["cidr"] = get_cidr_from_net_range(data_dictionary["netrange"])
    elif "inetnum" in data_dictionary:
        result["cidr"] = get_cidr_from_net_range(data_dictionary["inetnum"])
    else:
        result["cidr"] = "None"

    # Name
    if name != "None":
        result["name"] = name
    elif "name" in data_dictionary:
        result["name"] = data_dictionary["name"]
    elif "orgname" in data_dictionary:
        result["name"] = data_dictionary["orgname"]
    elif "org-name" in data_dictionary:
        result["name"] = data_dictionary["org-name"]
    elif "netname" in data_dictionary:
        result["name"] = data_dictionary["netname"]
    else:
        result["name"] = "None"

    # if IP isn't registered, the mask of whole IPv4 range is returned (eg IP 194.31.224.157)
    # Description of the query: This object represents all IPv4 addresses. If you see this object as a result of a
    # single IP query, it means that the IP address you are querying is currently not assigned to any organisation
    if result["cidr"] == "0.0.0.0/32":
        result["cidr"] = "None"
        result["asn"] = "None"
        result["country"] = "None"
        result["name"] = "None"

    return result


def parse_raw_query(query):
    # remove comments and empty lines
    lines = []

    responses = []

    if "% Information related to" not in query:
        print("### No information header")

    for line in query.split("\n"):
        # remove comments
        if line.startswith("#"):
            # start a new response section when '# start' is read
            if "start" in line:
                responses.append(Response)
            continue
        # remove comments
        if line.startswith("%"):
            if line.startswith("% Information related to"):
                responses.append(Response)
                cidr, asn = get_cidr_from_whois_header(line)
                if new_header == last_header:
                    new_header = last_header + "_"
                last_header = new_header
                responses[last_header] = []
                if asn != "None":
                    responses[last_header].append("asn: " + asn)
            continue
        # remove empty lines
        if line == "":
            continue
        # ignore lines that don't follow the 'key: value' format
        if ": " not in line:
            continue

        # if no responses are already in the array, start a new response
        if len(responses) == 0:
            responses.append(Response)

        responses[-1].data.append(line)
        lines.append(line)

    # the first thing in the response is information about the server. So the server's CIDR, name and country code
    # are returned instead of actual data. If results are read backwards, actual data will be read first
    lines.reverse()

    data_dictionary = {}

    for line in lines:
        # read key and value
        key, value = line.split(": ", 1)
        key = key.lower()

        # ignore repeating information from other servers (only first line with key gets read)
        if key in data_dictionary:
            continue

        data_dictionary[key] = value.strip()

    # only take first two letters of country code (country codes are always two letters, this removes comments)
    if "country" in data_dictionary:
        data_dictionary["country"] = data_dictionary["country"][0:2]

    # TODO: instead of one dictionaries, multiple responses are submitted
    return data_dictionary


def get_cidr_from_whois_header(line: str):
    line = line[25:]
    # range of ips
    if "-" in line:
        line = line.replace("\'", "")
        return get_cidr_from_net_range(line), "None"
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
            return "None"
        # subtract edge addresses to get size of network
        dif = int(max_address) - int(min_address)
        # use size to create IP, which will have all ones: 000.255.255.255
        inverted_mask = ipaddress.ip_address(dif)
        # from the lower IP and the inverted mask, ipaddress can parse the network cidr correctly
        network = ipaddress.IPv4Network(str(min_address) + "/" + str(inverted_mask))
    except:
        network = None
    return str(network)
