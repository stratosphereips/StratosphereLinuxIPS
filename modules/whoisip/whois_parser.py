import ipaddress

def get_data_from_response(response, asn, ctr_code, cidr, name):
    # get a dictionary of values in the response
    data_dictionary = parse_raw_response(response)

    result = {}

    # ASN
    # use original value if available
    if asn != "NA":
        result["asn"] = asn
    # use manually read value if available
    elif "asn" in data_dictionary:
        result["asn"] = data_dictionary["asn"]
    # otherwise set "NA"
    else:
        result["asn"] = "NA"

    # Country
    # TODO: This doesn't work for Namibia (code NA), but that's what the library returns
    # TODO: 163.194.132.190 is from US as far as cymruwhois says, but actually is in Australia. Who should I trust?
    if ctr_code != "NA":
        result["country"] = ctr_code
        if "country" in data_dictionary and data_dictionary["country"] != ctr_code:
            print("### Warning: Country code from cymruwhois is", ctr_code, ", but whois returned", data_dictionary["country"])
    elif "country" in data_dictionary:
        result["country"] = data_dictionary["country"]
    else:
        result["country"] = "NA"

    # CIDR
    if cidr != "NA":
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
        result["cidr"] = "NA"

    # Name
    if name != "NA":
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
        result["name"] = "NA"

    return result


def parse_raw_response(response):
    response = response.decode("utf-8")
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
    # get lower and higher IP strings from format 163.0.0.0 - 163.255.255.255
    min_address_str, max_address_str = netrange.split(" - ")
    # convert to IP address objects
    min_address = ipaddress.ip_address(min_address_str)
    max_address = ipaddress.ip_address(max_address_str)
    # only IPv4 addresses can be handled at the moment
    if min_address.version != 4:
        return "NA"
    # subtract edge addresses to get size of network
    dif = int(max_address) - int(min_address)
    # use size to create IP, which will have all ones: 000.255.255.255
    inverted_mask = ipaddress.ip_address(dif)
    # from the lower IP and the inverted mask, ipaddress can parse the network cidr correctly
    network = ipaddress.IPv4Network(str(min_address) + "/" + str(inverted_mask))
    return str(network)
