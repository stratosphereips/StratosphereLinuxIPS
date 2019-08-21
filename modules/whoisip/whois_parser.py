import ipaddress


class Response:
    def __init__(self, ip):
        self.ip = ip
        self.cidr = None
        self.asn = None
        self.updated = None
        self.country = None
        self.name = None
        self.orgid = None
        self.cidr_prefixlen = 0
        self.num_missing_values = 0
        self.important_fields = {"asn": None, "country": None, "cidr": None, "route": None, "netrange": None,
                                 "inetnum": None, "name": None, "orgname": None, "netname": None, "org-name": None,
                                 "last-modified": None}
        self.network = {}
        self.organization = {}
        self.role = {}
        self.key_translation = {"inetnum": "inetnum", "inet6num": "inetnum", "netrange": "inetnum",
                                "updated": "updated", "last-modified": "updated",
                                "org-name": "organization", "orgname": "organization", "organization": "organization",
                                "organisation": "organization", "role": "role"}
        self.processed_types = ["inetnum", "inet6num", "netrange", "organization", "orgname", "role"]
        self.type_dictionaries = {"inetnum": self.network, "organization": self.organization, "role": self.role}
        self.rir_server = ""

    def add_value_to_type(self, line, object_type):
        """
        Save a line of data (in a "key:     value" format) to the Response object
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
        Read data from the response and choose the correct values. Also, compute the statistics to evaluate the response
        :return: None
        """

        # I do a query for an IP, and get a response. Every successful response will have at least one section, and in
        #  each section,  there is the NetRange/inetnum/inet6num  type. I choose the smallest network and then:
        # - I get the last updated date of the network
        # - I get the country of the network
        # - I get the organization name from the network. This is in the format "org-name (org-id)"
        # - I get the ASN
        # If Organization info is included in the response:
        # - check the country if it was not set in the network
        # - ignore the update date of the organization, we don't care about it
        # If Organization is not set:
        # - I set netname as "name"
        # There are still some outliers.
        # For example, UPC isn't an Organization, but rather a Role (which is similar to Person, but can include more
        # people and people can change there). See whois -h whois.arin.net 213.220.193.103. I think role should be used
        #  if Org is not set rather than using netname from Network.
        # Sometimes the ASN is not set. This is also the case for UPC, where the ASN is included in the Route object.
        #  These are "interdomain routes" and the ASN there is "ASN of the AS that originates the route into the interAS
        #  routing system". Is it ok to use this?

        # if CIDR is given, use it. Otherwise parse it from netrange/inetnum
        # TODO: handle IPv6
        if "cidr" in self.network:
            self.cidr = self.network["cidr"]
        elif "inetnum" in self.network:
            self.cidr = get_cidr_from_net_range(self.network["inetnum"])

        if "updated" in self.network:
            self.updated = self.network["updated"]  # TODO: parse the time and save as unix

        if "country" in self.network:
            self.country = self.network["country"]
        elif "country" in self.organization:
            self.country = self.organization["country"]

        if "organization" in self.network:
            self.name, self.orgid = get_company_name_and_shortcut(self.network["organization"])
        if self.name is None:
            if "organization" in self.organization:
                self.name = self.organization["organization"]
            elif "netname" in self.network:
                self.name = self.network["netname"]
        if self.orgid is None and "orgid" in self.organization:
            self.orgid = self.organization["orgid"]

        if "originas" in self.network:
            self.asn = self.network["originas"]

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
    print()
    print("-------------------------------------------")
    print()
    print(ip)
    print()
    print("-------------------------------------------")
    print(query)
    responses = []
    last_type = ""

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

        last_type = responses[-1].add_value_to_type(line, last_type)

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


def get_company_name_and_shortcut(organization):
    if "(" not in organization:
        return organization, None
    else:
        # split by the last occurrence of "("
        orgname, orgid = organization.rsplit("(", 1)
        orgname = orgname.strip()
        orgid = orgid.replace(")", "").strip()
        return orgname, orgid
