import ipaddress


def get_data_from_response(response, asn, ctr_code, cidr, name):
    # get a dictionary of values in the response
    data_dictionary = parse_raw_response(response)

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


def parse_raw_response(response):
    # remove comments and empty lines
    lines = []

    for line in response.split("\n"):
        # remove comments
        if line.startswith("#"):
            continue
        # remove comments
        if line.startswith("%"):
            continue
        # remove empty lines
        if line == "":
            continue
        # ignore lines that don't follow the 'key: value' format
        if ": " not in line:
            continue
        lines.append(line)

    data_dictionary = {}

    for line in lines:
        # read key and value
        key, value = line.split(": ", 1)
        key = key.lower()

        # ignore repeating information from other servers (only first line with key gets read)
        if key in data_dictionary:
            continue

        data_dictionary[key] = value.strip()

    return data_dictionary


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
