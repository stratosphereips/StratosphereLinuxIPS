import subprocess

from modules.whoisip.whois_utils import *


class WhoisQuery:
    """
    WhoisQuery contains information gathered from one whois query. If it is initialized with some values, only missing
    fields will be filled, and provided data will not be changed. The query is started by calling self.run.
    """
    def __init__(self, ip, cidr=None, asn=None, country=None, name=None):
        """
        Initialize the result with default data. This may be anything known about the IP before the query. This data
        will not be changed
        :param ip: IP address that was processed
        :param cidr: network mask
        :param asn: Autonomous System Number
        :param country: country of origin
        :param name: name of the registering company (or the network itself)
        """
        # ip address that is to be checked
        self.ip = ip
        self.version = ip.version

        # network this ip belongs to
        self.cidr = cidr
        if self.cidr is not None:
            # number of bits in the mask
            self.cidr_prefixlen = int(self.cidr.split("/")[1])
        else:
            self.cidr_prefixlen = None
        # autonomous system number
        self.asn = asn
        # date of the last update in whois db (unix)
        self.updated = None
        # country of origin of the ip
        self.country = country
        # name of the organization that owns the ip. If it is not known, net name is used
        self.name = name
        # id of the organization (if organization is set). This is a short word, eg "GOGL" for "Google LLC"
        self.orgid = None
        # status of the query
        #            -1 : query was not yet run
        #             0 : query run without errors
        # anything else : there was an error, this is the code or message
        self.status = -1

        # compute how many values still need to be read when adding responses
        self.missing_values = 4

        if self.asn is not None:
            self.missing_values -= 1
        if self.cidr is not None:
            self.missing_values -= 1
        if self.country is not None:
            self.missing_values -= 1
        if self.name is not None:
            self.missing_values -= 1

    def add_response(self, response: Response):
        """
        Read values from the partial response and insert them to the result. If a value is set already, ignore it  
        :param response: one section of the query
        :return: None
        """
        if self.missing_values == 0:
            return

        if self.asn is None:
            if response.asn is not None:
                self.asn = response.asn
                self.missing_values -= 1
        if self.country is None:
            if response.country is not None:
                self.country = response.country
                self.missing_values -= 1
        if self.cidr is None:
            if response.cidr is not None:
                self.cidr = response.cidr
                self.cidr_prefixlen = response.cidr_prefixlen
                self.missing_values -= 1
        if self.name is None:
            if response.name is not None:
                self.name = response.name
                self.missing_values -= 1
        if self.updated is None:
            if response.updated is not None:
                self.updated = response.updated
                self.missing_values -= 1
        if self.orgid is None:
            if response.orgid is not None:
                self.orgid = response.orgid
                self.missing_values -= 1

    def get_result_dictionary(self):
        """
        Return the object as a dictionary that can be saved to the database.
        :return: Data dictionary containing a value or None. It has the following fields:
         - name: Name of the organization owning the IP
         - org_id: Short name of the organization
         - cidr: network in CIDR notation (IP/mask len)
         - cidr_prefix_len: length of the mask in prefix notation
         - country: two letter country code of the country where the network likely is
         - updated: unix date of when the network data was last updated on whois servers
         - status: status of the query (-1 for not yet run, 0 for OK, otherwise an error message/code)
         - asn: number of the autonomous system the IP is in
         - is_complete: True if all fields have a value. False if some fields were None.
        """
        result = {"name": self.name, "org_id": self.orgid, "cidr": self.cidr, "cidr_prefix_len": self.cidr_prefixlen,
                  "country": self.country, "updated": self.updated, "status": self.status, "asn": self.asn}

        is_complete = True
        for field in result:
            if field is None:
                is_complete = False
                break

        result["is_complete"] = is_complete
        return result

    def run(self):
        """
        Retrieve whois information for ip manually using the whois command. The query will read some basic information 
        and save it in the object. If something is already known about the IP, it will be left unchanged.
        If a field cannot be retrieved, it will remain None. If error occurs, the field will be None and the error will
        be returned and saved in self.status
        :return: error code, error message. For succesful queries, this will be 0, "OK"
        """

        # get whois result from terminal
        # to stop whois queries after a given time, the timeout command is called. This is because when time is limited
        # by subprocess, it is near impossible to read output of the terminated process.
        # Whois is contacting whois.arin.net (-h is the host), because servers follow different standards (if any) and
        # it is beyond the scope of this parser to read all of them
        timeout = 15
        # TODO: why 4?
        command = ["timeout", "--preserve-status", str(timeout) + "s", "whois", str(self.ip), "-h", "whois.arin.net"]

        # stdout: save output in response object
        # stderr: save error output in response object
        # universal newlines: output is string instead of byte array (this cannot be used due to encoding issues
        #    with foreign characters, eg French: 86.255.141.19)
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # handle errors (the --preserve-status option in timeout means that error codes thrown by whois will be used)
        if response.returncode != 0:
            # decode stderr (this fixes errors in French requests, but some czech chars are not correct in the comments)
            stderr = response.stderr.decode("iso-8859-1")
            if response.returncode == 2:
                # code 2 == network error? Idk, it doesn't say in the docs/man
                if len(response.stdout) == 0:
                    # if there is no response in stdout, likely there is no network connection
                    print(stderr)
                    self.status = str(response.returncode) + " - " + stderr
                    return response.returncode, stderr
                else:
                    # warning: there was a network issue, but some data was retrieved, will process it anyway
                    print("Whois on ip: " + self.ip + " timeouted, data might be incomplete")
            else:
                # other error codes except for 2
                self.status = str(response.returncode) + " - " + stderr
                return response.returncode, stderr

        # decode iso-8859-1, this fixes errors in French requests (but some Czech chars are not correct in the comments)
        output = response.stdout.decode("iso-8859-1")

        # get a set of responses: one query might contain multiple responses. This may be because multiple servers have
        # responded (the query was redirected), or because the IP is in multiple networks with different properties.
        # server response is the first response in the query, and usually describes the RIR responsible for the range
        # subnet responses is an array of more specific responses, and is sorted by smallest network first
        server_response, subnet_responses = parse_raw_query(self.ip, output)

        # process all responses
        # Because they are sorted, data will be most likely taken from the specific response, and only if that response
        # is incomplete, more general data will be used. In worst case scenario, server response is taken.
        for response in subnet_responses:
            self.add_response(response)

        if server_response is not None:
            self.add_response(server_response)

        return 0, "0K"
