
import json
import configparser
from .database import __database__
import ipaddress
import validators
import requests

class Whitelist():
    def __init__(self, outputqueue, config):
        self.name = 'whitelist'
        self.outputqueue = outputqueue
        self.config = config
        self.read_configuration()

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
        self.outputqueue.put(f"{levels}|{self.name}|{text}")

    def read_configuration(self):
        """ Read the configuration file for what we need """
        try:
            self.whitelist_path = self.config.get('parameters', 'whitelist_path')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            self.whitelist_path = 'whitelist.conf'

    def read_whitelist(self):
        """ Reads the content of whitelist.conf and stores information about each ip/org/domain in the database """

        # since this function can be run when the user modifies whitelist.conf
        # we need to check if the dicts are already there
        whitelisted_IPs = __database__.get_whitelist('IPs')
        whitelisted_domains = __database__.get_whitelist('domains')
        whitelisted_orgs = __database__.get_whitelist('organizations')
        whitelisted_mac = __database__.get_whitelist('mac')

        try:
            with open(self.whitelist_path) as whitelist:
                # Process lines after comments
                line_number = 0
                line = whitelist.readline()
                while line:
                    line_number+=1
                    if line.startswith('"IoCType"'):
                        line = whitelist.readline()
                        continue

                    # check if the user commented an org, ip or domain that was whitelisted
                    if line.startswith('#'):
                        if whitelisted_IPs:
                            for ip in list(whitelisted_IPs):
                                # make sure the user commented the line we have in cache exactly
                                if ip in line and whitelisted_IPs[ip]['from'] in line and whitelisted_IPs[ip]['what_to_ignore'] in line:
                                    # remove that entry from whitelisted_ips
                                    whitelisted_IPs.pop(ip)
                                    break

                        if whitelisted_domains:
                            for domain in list(whitelisted_domains):
                                if domain in line \
                                and whitelisted_domains[domain]['from'] in line \
                                and whitelisted_domains[domain]['what_to_ignore'] in line:
                                    # remove that entry from whitelisted_domains
                                    whitelisted_domains.pop(domain)
                                    break

                        if whitelisted_orgs:
                            for org in list(whitelisted_orgs):
                                if org in line \
                                and whitelisted_orgs[org]['from'] in line \
                                and whitelisted_orgs[org]['what_to_ignore'] in line:
                                    # remove that entry from whitelisted_domains
                                    whitelisted_orgs.pop(org)
                                    break

                        # todo if the user closes slips, changes the whitelist, and reopens slips , slips will still have the old whitelist in the cache!
                        line = whitelist.readline()
                        continue
                    # line should be: ["type","domain/ip/organization","from","what_to_ignore"]
                    line = line.replace("\n","").replace(" ","").split(",")
                    try:
                        type_ , data, from_ , what_to_ignore = (line[0]).lower(), line[1], line[2], line[3]
                    except IndexError:
                        # line is missing a column, ignore it.
                        self.print(f"Line {line_number} in whitelist.conf is missing a column. Skipping.")
                        line = whitelist.readline()
                        continue

                    # Validate the type before processing
                    try:
                        if ('ip' in type_ and
                            (validators.ip_address.ipv6(data) or validators.ip_address.ipv4(data))):
                            whitelisted_IPs[data] = {'from': from_, 'what_to_ignore': what_to_ignore}
                        elif 'domain' in type_ and validators.domain(data):
                            whitelisted_domains[data] = {'from': from_, 'what_to_ignore': what_to_ignore}
                        elif 'mac' in type_ and validators.mac_address(data):
                            whitelisted_mac[data] = {'from': from_, 'what_to_ignore': what_to_ignore}
                        elif 'org' in type_:
                            #organizations dicts look something like this:
                            #  {'google': {'from':'dst',
                            #               'what_to_ignore': 'alerts'
                            #               'IPs': {'34.64.0.0/10': subnet}}
                            try:
                                # org already whitelisted, update info
                                whitelisted_orgs[data]['from'] = from_
                                whitelisted_orgs[data]['what_to_ignore'] = what_to_ignore
                            except KeyError:
                                # first time seeing this org
                                whitelisted_orgs[data] = {'from' : from_, 'what_to_ignore' : what_to_ignore}

                        else:
                            self.print(f"{data} is not a valid {type_}.",1,0)
                    except:
                        self.print(f"Line {line_number} in whitelist.conf is invalid. Skipping.")
                    line = whitelist.readline()
        except FileNotFoundError:
            self.print(f"Can't find {self.whitelist_path}, using slips default whitelist.conf instead")
            if self.whitelist_path != 'whitelist.conf':
                self.whitelist_path = 'whitelist.conf'
                self.read_whitelist()


        # after we're done reading the file, process organizations info and store in the db
        orgs_in_cache = __database__.get_whitelist('organizations')
        for org in whitelisted_orgs:
            # make sure we don't already have info about this org in the cache db
            if orgs_in_cache and org in orgs_in_cache:
                # we have orgs in cache but do we have this org?
                # if we have the org in cache , we have its ips domains and asn, skip it
                continue

            # Store the IPs, domains and asn of this org in the db
            org_subnets = self.load_org_IPs(org)
            if org_subnets:
                # Store the IPs of this org
                whitelisted_orgs[org].update({'IPs' : json.dumps(org_subnets)})

            org_domains = self.load_org_domains(org)
            if org_domains:
                # Store the ASN of this org
                whitelisted_orgs[org].update({'domains' : json.dumps(org_domains)})

            org_asn = self.load_org_asn(org)
            if org_asn:
                # Store the ASN of this org
                whitelisted_orgs[org].update({'asn' : json.dumps(org_asn)})

        # store everything in the cache db because we'll be needing this info in the evidenceProcess
        __database__.set_whitelist("IPs", whitelisted_IPs)
        __database__.set_whitelist("domains", whitelisted_domains)
        __database__.set_whitelist("organizations", whitelisted_orgs)
        __database__.set_whitelist("mac", whitelisted_mac)

        return line_number

    def load_org_asn(self, org) -> list :
        """
        Reads the specified org's asn from slips_files/organizations_info and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's asn
        """
        try:
            # Each file is named after the organization's name followed by _asn
            org_asn =[]
            file = f'slips_files/organizations_info/{org}_asn'
            with open(file,'r') as f:
                line = f.readline()
                while line:
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace("\n","").strip()
                    # Read all as upper
                    org_asn.append(line.upper())
                    line = f.readline()
            return org_asn

        except (FileNotFoundError, IOError):
            # theres no slips_files/organizations_info/{org}_asn for this org
            # see if the org has asn cached in our db
            asn_cache = __database__.get_asn_cache()
            org_asn =[]
            for asn in asn_cache:
                if org in asn.lower():
                    org_asn.append(org)
            if org_asn != []: return org_asn
            return False

    def load_org_domains(self, org) -> list :
        """
        Reads the specified org's domains from slips_files/organizations_info and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's domains
        """
        try:
            # Each file is named after the organization's name followed by _domains
            domains =[]
            file = f'slips_files/organizations_info/{org}_domains'
            with open(file,'r') as f:
                line = f.readline()
                while line:
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace("\n","").strip()
                    domains.append(line.lower())
                    line = f.readline()
            return domains
        except (FileNotFoundError, IOError):
            return False
    
    def get_domains_of_flow(self, column_values):
        """ Returns the domains of each ip (src and dst) that appeard in this flow """
        # These separate lists, hold the domains that we should only check if they are SRC or DST. Not both
        domains_to_check_src = []
        domains_to_check_dst = []
        try:
            #self.print(f"IPData of src IP {column_values['saddr']}: {__database__.getIPData(column_values['saddr'])}")
            ip_data = __database__.getIPData(column_values['saddr'])
            if ip_data:
                sni_info = ip_data.get('SNI',[{}])[0]
                if sni_info: domains_to_check_src.append(sni_info.get('server_name'))
        except (KeyError, TypeError):
            pass
        try:
            #self.print(f"DNS of src IP {column_values['saddr']}: {__database__.get_dns_resolution(column_values['saddr'])}")
            src_dns_domains = __database__.get_dns_resolution(column_values['saddr'])
            src_dns_domains = src_dns_domains.get('domains', [])
            for dns_domain in src_dns_domains:
                domains_to_check_src.append(dns_domain)
        except (KeyError, TypeError):
            pass
        try:
            # self.print(f"IPData of dst IP {column_values['daddr']}: {__database__.getIPData(column_values['daddr'])}")
            ip_data = __database__.getIPData(column_values['daddr'])
            if ip_data:
                sni_info = ip_data.get('SNI',[{}])[0]
                if sni_info:
                    domains_to_check_dst.append(sni_info.get('server_name'))
        except (KeyError, TypeError):
            pass
        return domains_to_check_dst, domains_to_check_src

    
    def is_whitelisted(self, column_values) -> bool:
        """
        Checks if the src IP or dst IP or domain or organization of this flow is whitelisted.
        """
        #self.print(f'List of whitelist: Domains: {whitelisted_domains}, IPs: {whitelisted_IPs}, Orgs: {whitelisted_orgs}')

        # check if we have domains whitelisted
        whitelisted_domains = __database__.get_whitelist('domains')
        if whitelisted_domains:
            #self.print('Check the domains')
            # Check if the domain is whitelisted
            # Domain names are stored in different zeek files using different names.
            # Try to get the domain from each file.
            domains_to_check = []
            ssl_domain = column_values.get('server_name','') # ssl.log
            domains_to_check.append(ssl_domain)
            http_domain = column_values.get('host','') # http.log
            domains_to_check.append(http_domain)
            notice_domain = column_values.get('sub','').replace("CN=","") # in notice.log
            domains_to_check.append(notice_domain)

            domains_to_check_dst, domains_to_check_src = self.get_domains_of_flow(column_values)

            try:
                #self.print(f"DNS of dst IP {column_values['daddr']}: {__database__.get_dns_resolution(column_values['daddr'])}")
                dst_dns_domains = __database__.get_dns_resolution(column_values['daddr'])
                dst_dns_domains = dst_dns_domains.get('domains', [])
                for dns_domain in dst_dns_domains:
                    domains_to_check_dst.append(dns_domain)
            except (KeyError, TypeError):
                pass

            #self.print(f'Domains to check from flow: {domains_to_check}, {domains_to_check_dst} {domains_to_check_src}')
            # Go through each whitelisted domain and check if what arrived is there
            for domain in list(whitelisted_domains.keys()):
                what_to_ignore = whitelisted_domains[domain]['what_to_ignore']
                # Here we iterate over all the domains to check so we can find
                # subdomains. If slack.com was whitelisted, then test.slack.com
                # should be ignored too. But not 'slack.com.test'
                for domain_to_check in domains_to_check:
                    main_domain = domain_to_check[-len(domain):]
                    if domain in main_domain:
                        # We can ignore flows or alerts, what is it?
                        if 'flows' in what_to_ignore or 'both' in what_to_ignore:
                            # self.print(f'Whitelisting the domain {domain_to_check} due to whitelist of {domain}')
                            return True

                # do we wanna whitelist flows coming from or going to this domain or both?
                from_ = whitelisted_domains[domain]['from']

                # Now check the related domains of the src IP
                if 'src' in from_ or 'both' in from_:
                    for domain_to_check in domains_to_check_src:
                        main_domain = domain_to_check[-len(domain):]
                        if domain in main_domain:
                            # We can ignore flows or alerts, what is it?
                            if 'flows' in what_to_ignore or 'both' in what_to_ignore:
                                # self.print(f"Whitelisting the domain {domain_to_check} because is related to domain {domain} of src IP {column_values['saddr']}")
                                return True

                # Now check the related domains of the dst IP
                if 'dst' in from_ or 'both' in from_:
                    for domain_to_check in domains_to_check_dst:
                        main_domain = domain_to_check[-len(domain):]
                        if domain in main_domain:
                            # We can ignore flows or alerts, what is it?
                            if 'flows' in what_to_ignore or 'both' in what_to_ignore:
                                # self.print(f"Whitelisting the domain {domain_to_check} because is related"
                                #            f" to domain {domain} of dst IP {column_values['daddr']}")
                                return True

        saddr = column_values['saddr']
        daddr = column_values['daddr']

        # check if we have IPs whitelisted
        whitelisted_IPs = __database__.get_whitelist('IPs')

        if whitelisted_IPs:
            #self.print('Check the IPs')
            # Check if the IPs are whitelisted
            ips_to_whitelist = list(whitelisted_IPs.keys())

            if saddr in ips_to_whitelist:
                # The flow has the src IP to whitelist
                from_ = whitelisted_IPs[saddr]['from']
                what_to_ignore = whitelisted_IPs[saddr]['what_to_ignore']
                if ('src' in from_ or 'both' in from_) and ('flows' in what_to_ignore or 'both' in what_to_ignore):
                    # self.print(f"Whitelisting the src IP {column_values['saddr']}")
                    return True

            if daddr in ips_to_whitelist: # should be if and not elif
                # The flow has the dst IP to whitelist
                from_ = whitelisted_IPs[daddr]['from']
                what_to_ignore = whitelisted_IPs[daddr]['what_to_ignore']
                if ('dst' in from_  or 'both' in from_) and ('flows' in what_to_ignore or 'both' in what_to_ignore):
                    # self.print(f"Whitelisting the dst IP {column_values['daddr']}")
                    return True

        # check if we have orgs whitelisted
        whitelisted_orgs = __database__.get_whitelist('organizations')

        # Check if the orgs are whitelisted
        if whitelisted_orgs:
            #self.print('Check if the organization is whitelisted')
            # Check if IP belongs to a whitelisted organization range
            # Check if the ASN of this IP is any of these organizations

            for org in whitelisted_orgs:
                from_ =  whitelisted_orgs[org]['from'] # src or dst or both
                what_to_ignore = whitelisted_orgs[org]['what_to_ignore'] # flows, alerts or both
                #self.print(f'Checking {org}, from:{from_} type {what_to_ignore}')

                # get the domains of this flow
                domains_to_check_dst, domains_to_check_src = self.get_domains_of_flow()

                if 'flows' in what_to_ignore or 'both' in what_to_ignore:
                    # We want to block flows from this org. get the domains of this flow based on the direction.
                    if 'both' in from_ : domains_to_check = domains_to_check_src + domains_to_check_dst
                    elif 'src' in from_: domains_to_check = domains_to_check_src
                    elif 'dst' in from_: domains_to_check = domains_to_check_dst
                    # get the ips of this org?? #todo
                    org_subnets = json.loads(whitelisted_orgs[org].get('IPs','{}'))


                    if 'src' in from_ or 'both' in from_:
                        # Method 1 Check if src IP belongs to a whitelisted organization range
                        for network in org_subnets:
                            try:
                                ip = ipaddress.ip_address(saddr)
                                if ip in ipaddress.ip_network(network):
                                    # self.print(f"The src IP {saddr} is in the range {network} or org {org}. Whitelisted.")
                                    return True
                            except ValueError:
                                # Some flows don't have IPs, but mac address or just - in some cases
                                return False


                        # Method 2 Check if the ASN of this src IP is any of these organizations
                        ip_data = __database__.getIPData(saddr)
                        try:
                            ip_asn = ip_data['asn']['asnorg']
                            if ip_asn and ip_asn != 'Unknown' and (org.lower() in ip_asn.lower() or ip_asn in whitelisted_orgs[org]['asn']):
                                # this ip belongs to a whitelisted org, ignore flow
                                # self.print(f"The ASN {ip_asn} of IP {saddr} is in the values of org {org}. Whitelisted.")
                                return True
                        except (KeyError, TypeError):
                            # No asn data for src ip
                            pass

                        # Method 3 Check if the domains of this flow belong to this org
                        org_domains = json.loads(whitelisted_orgs[org].get('domains','{}'))
                        # domains to check are usually 1 or 2 domains
                        for flow_domain in domains_to_check:
                            if org in flow_domain:
                                # self.print(f"The domain of this flow ({flow_domain}) belongs to the domains of {org}")
                                return True

                            flow_TLD = flow_domain.split(".")[-1]
                            for org_domain in org_domains:
                                org_domain_TLD = org_domain.split(".")[-1]
                                # make sure the 2 domains have the same same top level domain
                                if flow_TLD != org_domain_TLD: continue

                                # match subdomains too
                                # if org has org.com, and the flow_domain is xyz.org.com whitelist it
                                if org_domain in flow_domain:
                                    # print(f"The src domain of this flow ({flow_domain}) is "
                                    #            f"a subdomain of {org} domain: {org_domain}")
                                    return True
                                # if org has xyz.org.com, and the flow_domain is org.com whitelist it
                                if flow_domain in org_domain :
                                    # print(f"The domain of {org} ({org_domain}) is a subdomain of "
                                    #       f"this flow domain ({flow_domain})")
                                    return True

                    if 'dst' in from_ or 'both' in from_:
                        # Method 1 Check if dst IP belongs to a whitelisted organization range
                        for network in org_subnets:
                            try:
                                ip = ipaddress.ip_address(column_values['daddr'])
                                if ip in ipaddress.ip_network(network):
                                    # self.print(f"The dst IP {column_values['daddr']} "
                                    #            f"is in the range {network} or org {org}. Whitelisted.")
                                    return True
                            except ValueError:
                                # Some flows don't have IPs, but mac address or just - in some cases
                                return False
                        # Method 2 Check if the ASN of this dst IP is any of these organizations
                        ip_data = __database__.getIPData(column_values['daddr'])
                        try:
                            ip_asn = ip_data['asn']['asnorg']
                            if ip_asn and ip_asn != 'Unknown' and (org.lower() in ip_asn.lower() or ip_asn in whitelisted_orgs[org]['asn']):
                                # this ip belongs to a whitelisted org, ignore flow
                                # self.print(f"The ASN {ip_asn} of IP {column_values['daddr']} "
                                #            f"is in the values of org {org}. Whitelisted.")
                                return True
                        except (KeyError, TypeError):
                            # No asn data for src ip
                            pass

                        # Method 3 Check if the domains of this flow belong to this org
                        for domain in org_domains:
                            # domains to check are usually 1 or 2 domains
                            for flow_domain in domains_to_check:
                                # match subdomains too
                                if domain in flow_domain:
                                    # self.print(f"The dst domain of this flow ({flow_domain}) is "
                                    #            f"a subdomain of {org} domain: {domain}")
                                    return True

        # check if we have mac addresses whitelisted
        whitelisted_mac = __database__.get_whitelist('mac')

        if whitelisted_mac:

            # try to get the mac address of the current flow
            src_mac =  column_values.get('src_mac',False)
            if not src_mac:
                src_mac = column_values.get('mac',False)
            if not src_mac:
                src_mac = __database__.get_mac_addr_from_profile(f'profile_{saddr}')[0]

            if src_mac and src_mac in list(whitelisted_mac.keys()):
                # the src mac of this flow is whitelisted, but which direction?
                from_ = whitelisted_mac[src_mac]['from']
                if 'src' in from_ or 'both' in from_:
                    # self.print(f"The source MAC of this flow {src_mac} is whitelisted")
                    return True

            dst_mac = column_values.get('dst_mac',False)
            if dst_mac and dst_mac in list(whitelisted_mac.keys()):
                # the dst mac of this flow is whitelisted, but which direction?
                from_ = whitelisted_mac[dst_mac]['from']
                if 'dst' in from_ or 'both' in from_:
                    # self.print(f"The dst MAC of this flow {dst_mac} is whitelisted")
                    return True

        return False

    def load_org_IPs(self, org) -> list :
        """
        Reads the specified org's info from slips_files/organizations_info and stores the info in the database
        if there's no file for this org, it get the IP ranges from asnlookup.com
        org: 'google', 'facebook', 'twitter', etc...
        returns a list of this organization's subnets
        """
        try:
            # Each file is named after the organization's name
            # Each line of the file containes an ip range, for example: 34.64.0.0/10
            org_subnets = []
            file = f'slips_files/organizations_info/{org}'
            with open(file,'r') as f:
                line = f.readline()
                while line:
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace("\n","").strip()
                    try:
                        # make sure this line is a valid network
                        is_valid_line = ipaddress.ip_network(line)
                        org_subnets.append(line)
                    except ValueError:
                        # not a valid line, ignore it
                        pass
                    line = f.readline()
            return org_subnets
        except (FileNotFoundError, IOError):
            # there's no slips_files/organizations_info/{org} for this org
            org_subnets = []
            # see if we can get asn about this org
            try:
                response = requests.get('http://asnlookup.com/api/lookup?org=' + org.replace('_', ' '),
                                        headers ={  'User-Agent': 'ASNLookup PY/Client'}, timeout = 10)
            except requests.exceptions.ConnectionError:
                # Connection reset by peer
                return False
            ip_space = json.loads(response.text)
            if ip_space:
                with open(f'slips_files/organizations_info/{org}','w') as f:
                    for subnet in ip_space:
                        # get ipv4 only
                        if ':' not in subnet:
                            try:
                                # make sure this line is a valid network
                                is_valid_line = ipaddress.ip_network(subnet)
                                f.write(subnet + '\n')
                                org_subnets.append(subnet)
                            except ValueError:
                                # not a valid line, ignore it
                                continue
                return org_subnets
            else:
                # can't get org IPs from asnlookup.com
                return False