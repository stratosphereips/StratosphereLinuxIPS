import json
import configparser
from slips_files.core.database.database import __database__
import ipaddress
import validators
from slips_files.common.slips_utils import utils
import re
import os


class Whitelist:
    def __init__(self, outputqueue, config, redis_port):
        self.name = 'whitelist'
        self.outputqueue = outputqueue
        self.config = config
        self.read_configuration()
        self.org_info_path = 'slips_files/organizations_info/'
        self.ignored_flow_types = ('arp')
        __database__.start(self.config, redis_port)


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
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

    def read_configuration(self):
        """Read the configuration file for what we need"""
        try:
            self.whitelist_path = self.config.get(
                'parameters', 'whitelist_path'
            )
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
        ):
            self.whitelist_path = 'whitelist.conf'

    def is_whitelisted_asn(self, ip, org):
        ip_data = __database__.getIPData(ip)
        try:
            ip_asn = ip_data['asn']['asnorg']
            org_asn = json.loads(__database__.get_org_info(org, 'asn'))
            if (
                ip_asn
                and ip_asn != 'Unknown'
                and (org.lower() in ip_asn.lower() or ip_asn in org_asn)
            ):
                # this ip belongs to a whitelisted org, ignore flow
                # self.print(f"The ASN {ip_asn} of IP {column_values['daddr']} "
                #            f"is in the values of org {org}. Whitelisted.")
                return True
        except (KeyError, TypeError):
            # No asn data for src ip
            pass

    def is_ignored_flow_type(self, flow_type) -> bool:
        """
        Function reduce the number of checks we make if we fon't need to check this type of flow
        """
        if flow_type in self.ignored_flow_types:
            return True


    def is_whitelisted_flow(self, column_values, flow_type) -> bool:
        """
        Checks if the src IP or dst IP or domain or organization of this flow is whitelisted.
        """

        if whitelisted_domains := __database__.get_whitelist('domains'):
            ssl_domain = column_values.get('server_name', '')  # ssl.log
            # Domain names are stored in different zeek files using different names.
            # Try to get the domain from each file.            domains_to_check = [ssl_domain]
            domains_to_check = [ssl_domain]
            http_domain = column_values.get('host', '')  # http.log
            domains_to_check.append(http_domain)
            notice_domain = column_values.get('sub', '').replace(
                'CN=', ''
            )  # in notice.log
            domains_to_check.append(notice_domain)

            (
                domains_to_check_dst,
                domains_to_check_src,
            ) = self.get_domains_of_flow(column_values)

            try:
                # self.print(f"DNS of dst IP {column_values['daddr']}: {__database__.get_dns_resolution(column_values['daddr'])}")
                dst_dns_domains = __database__.get_reverse_dns(
                    column_values['daddr']
                )
                dst_dns_domains = dst_dns_domains.get('domains', [])
                for dns_domain in dst_dns_domains:
                    domains_to_check_dst.append(dns_domain)
            except (KeyError, TypeError):
                pass

            # self.print(f'Domains to check from flow: {domains_to_check}, {domains_to_check_dst} {domains_to_check_src}')
            # Go through each whitelisted domain and check if what arrived is there
            for domain in list(whitelisted_domains.keys()):
                what_to_ignore = whitelisted_domains[domain]['what_to_ignore']
                # Here we iterate over all the domains to check so we can find
                # subdomains. If slack.com was whitelisted, then test.slack.com
                # should be ignored too. But not 'slack.com.test'
                for domain_to_check in domains_to_check:
                    main_domain = domain_to_check[-len(domain) :]
                    if domain in main_domain:
                        # We can ignore flows or alerts, what is it?
                        if (
                            'flows' in what_to_ignore
                            or 'both' in what_to_ignore
                        ):
                            # self.print(f'Whitelisting the domain {domain_to_check} due to whitelist of {domain}')
                            return True

                # do we wanna whitelist flows coming from or going to this domain or both?
                from_ = whitelisted_domains[domain]['from']

                # Now check the related domains of the src IP
                if 'src' in from_ or 'both' in from_:
                    for domain_to_check in domains_to_check_src:
                        main_domain = domain_to_check[-len(domain) :]
                        if domain in main_domain:
                            # We can ignore flows or alerts, what is it?
                            if (
                                'flows' in what_to_ignore
                                or 'both' in what_to_ignore
                            ):
                                # self.print(f"Whitelisting the domain {domain_to_check} because is related to domain {domain} of src IP {column_values['saddr']}")
                                return True

                # Now check the related domains of the dst IP
                if 'dst' in from_ or 'both' in from_:
                    for domain_to_check in domains_to_check_dst:
                        main_domain = domain_to_check[-len(domain) :]
                        if domain in main_domain:
                            # We can ignore flows or alerts, what is it?
                            if (
                                'flows' in what_to_ignore
                                or 'both' in what_to_ignore
                            ):
                                # self.print(f"Whitelisting the domain {domain_to_check} because is related"
                                #            f" to domain {domain} of dst IP {column_values['daddr']}")
                                return True

        saddr = column_values['saddr']
        daddr = column_values['daddr']

        if whitelisted_IPs := __database__.get_whitelist('IPs'):
            # self.print('Check the IPs')
            # Check if the IPs are whitelisted
            ips_to_whitelist = list(whitelisted_IPs.keys())

            if saddr in ips_to_whitelist:
                # The flow has the src IP to whitelist
                from_ = whitelisted_IPs[saddr]['from']
                what_to_ignore = whitelisted_IPs[saddr]['what_to_ignore']
                if ('src' in from_ or 'both' in from_) and (
                        'flows' in what_to_ignore or 'both' in what_to_ignore
                ):
                    # self.print(f"Whitelisting the src IP {column_values['saddr']}")
                    return True

            if daddr in ips_to_whitelist:   # should be if and not elif
                # The flow has the dst IP to whitelist
                from_ = whitelisted_IPs[daddr]['from']
                what_to_ignore = whitelisted_IPs[daddr]['what_to_ignore']
                if ('dst' in from_ or 'both' in from_) and (
                    'flows' in what_to_ignore or 'both' in what_to_ignore
                ):
                    # self.print(f"Whitelisting the dst IP {column_values['daddr']}")
                    return True

        if whitelisted_mac := __database__.get_whitelist('mac'):
            # try to get the mac address of the current flow
            src_mac = column_values.get('src_mac', False)
            if not src_mac:
                src_mac = column_values.get('mac', False)
            if not src_mac:
                src_mac = __database__.get_mac_addr_from_profile(
                    f'profile_{saddr}'
                )[0]

            if src_mac and src_mac in list(whitelisted_mac.keys()):
                # the src mac of this flow is whitelisted, but which direction?
                from_ = whitelisted_mac[src_mac]['from']
                if 'src' in from_ or 'both' in from_:
                    # self.print(f"The source MAC of this flow {src_mac} is whitelisted")
                    return True

            dst_mac = column_values.get('dst_mac', False)
            if dst_mac and dst_mac in list(whitelisted_mac.keys()):
                # the dst mac of this flow is whitelisted, but which direction?
                from_ = whitelisted_mac[dst_mac]['from']
                if 'dst' in from_ or 'both' in from_:
                    # self.print(f"The dst MAC of this flow {dst_mac} is whitelisted")
                    return True

        if self.is_ignored_flow_type(flow_type):
            return False

        if whitelisted_orgs := __database__.get_whitelist('organizations'):
            # self.print('Check if the organization is whitelisted')
            # Check if IP belongs to a whitelisted organization range
            # Check if the ASN of this IP is any of these organizations

            for org in whitelisted_orgs:
                from_ = whitelisted_orgs[org]['from']  # src or dst or both
                what_to_ignore = whitelisted_orgs[org][
                    'what_to_ignore'
                ]  # flows, alerts or both
                # self.print(f'Checking {org}, from:{from_} type {what_to_ignore}')

                # get the domains of this flow
                (
                    domains_to_check_dst,
                    domains_to_check_src,
                ) = self.get_domains_of_flow(column_values)

                if 'flows' in what_to_ignore or 'both' in what_to_ignore:
                    # We want to block flows from this org. get the domains of this flow based on the direction.
                    if 'both' in from_:
                        domains_to_check = (
                            domains_to_check_src + domains_to_check_dst
                        )
                    elif 'src' in from_:
                        domains_to_check = domains_to_check_src
                    elif 'dst' in from_:
                        domains_to_check = domains_to_check_dst

                    if 'src' in from_ or 'both' in from_:
                        # Method 1 Check if src IP belongs to a whitelisted organization range
                        try:
                            if self.is_ip_in_org(saddr, org):
                                #self.print(f"The src IP {saddr} is in the ranges of org {org}. Whitelisted.")
                                return True
                        except ValueError:
                            # Some flows don't have IPs, but mac address or just - in some cases
                            return False

                        # Method 2 Check if the ASN of this src IP is any of these organizations
                        if self.is_whitelisted_asn(saddr, org):
                            # this ip belongs to a whitelisted org, ignore flow
                            # self.print(f"The src IP {saddr} belong to {org}. Whitelisted because of ASN.")
                            return True

                    if 'dst' in from_ or 'both' in from_:
                        # Method 1 Check if dst IP belongs to a whitelisted organization range
                        try:
                            if self.is_ip_in_org(column_values['daddr'], org):
                                # self.print(f"The dst IP {column_values['daddr']} "
                                # f"is in the range {network} or org {org}. Whitelisted.")
                                return True
                        except ValueError:
                            # Some flows don't have IPs, but mac address or just - in some cases
                            return False

                        # Method 2 Check if the ASN of this dst IP is any of these organizations
                        if self.is_whitelisted_asn(daddr, org):
                            # this ip belongs to a whitelisted org, ignore flow
                            return True

                    # either we're blocking src, dst, or both check the domain of this flow
                    # Method 3 Check if the domains of this flow belong to this org
                    # domains to check are usually 1 or 2 domains
                    for flow_domain in domains_to_check:
                        if self.is_domain_in_org(flow_domain, org):
                            return True

        return False

    def is_domain_in_org(self, domain, org):
        """
        Checks if the given domains belongs to the given org
        """
        org_domains = json.loads(
            __database__.get_org_info(org, 'domains')
        )
        if org in domain:
            # self.print(f"The domain of this flow ({flow_domain}) belongs to the domains of {org}")
            return True

        flow_TLD = domain.split('.')[-1]
        for org_domain in org_domains:
            org_domain_TLD = org_domain.split('.')[-1]
            # make sure the 2 domains have the same same top level domain
            if flow_TLD != org_domain_TLD:
                continue

            # match subdomains too
            # if org has org.com, and the flow_domain is xyz.org.com whitelist it
            if org_domain in domain:
                # self.print(f"The src domain of this flow ({flow_domain}) is "
                #            f"a subdomain of {org} domain: {org_domain}")
                return True
            # if org has xyz.org.com, and the flow_domain is org.com whitelist it
            if domain in org_domain:
                # self.print(f"The domain of {org} ({org_domain}) is a subdomain of "
                #       f"this flow domain ({flow_domain})")
                return True

    def read_whitelist(self):
        """Reads the content of whitelist.conf and stores information about each ip/org/domain in the database"""

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
                # line = whitelist.readline()
                while line := whitelist.readline():
                    line_number += 1
                    if line.startswith('"IoCType"'):
                        continue

                    # check if the user commented an org, ip or domain that was whitelisted
                    if line.startswith('#'):
                        if whitelisted_IPs:
                            for ip in list(whitelisted_IPs):
                                # make sure the user commented the line we have in cache exactly
                                if (
                                    ip in line
                                    and whitelisted_IPs[ip]['from'] in line
                                    and whitelisted_IPs[ip]['what_to_ignore']
                                    in line
                                ):
                                    # remove that entry from whitelisted_ips
                                    whitelisted_IPs.pop(ip)
                                    break

                        if whitelisted_domains:
                            for domain in list(whitelisted_domains):
                                if (
                                    domain in line
                                    and whitelisted_domains[domain]['from']
                                    in line
                                    and whitelisted_domains[domain][
                                        'what_to_ignore'
                                    ]
                                    in line
                                ):
                                    # remove that entry from whitelisted_domains
                                    whitelisted_domains.pop(domain)
                                    break

                        if whitelisted_orgs:
                            for org in list(whitelisted_orgs):
                                if (
                                    org in line
                                    and whitelisted_orgs[org]['from'] in line
                                    and whitelisted_orgs[org]['what_to_ignore']
                                    in line
                                ):
                                    # remove that entry from whitelisted_domains
                                    whitelisted_orgs.pop(org)
                                    break

                        # todo if the user closes slips, changes the whitelist, and reopens slips ,
                        #  slips will still have the old whitelist in the cache!
                        continue
                    # line should be: ["type","domain/ip/organization","from","what_to_ignore"]
                    line = line.replace('\n', '').replace(' ', '').split(',')
                    try:
                        type_, data, from_, what_to_ignore = (
                            (line[0]).lower(),
                            line[1],
                            line[2],
                            line[3],
                        )
                    except IndexError:
                        # line is missing a column, ignore it.
                        self.print(
                            f'Line {line_number} in whitelist.conf is missing a column. Skipping.'
                        )
                        continue

                    # Validate the type before processing
                    try:
                        if 'ip' in type_ and (
                            validators.ip_address.ipv6(data)
                            or validators.ip_address.ipv4(data)
                        ):
                            whitelisted_IPs[data] = {
                                'from': from_,
                                'what_to_ignore': what_to_ignore,
                            }
                        elif 'domain' in type_ and validators.domain(data):
                            whitelisted_domains[data] = {
                                'from': from_,
                                'what_to_ignore': what_to_ignore,
                            }
                        elif 'mac' in type_ and validators.mac_address(data):
                            whitelisted_mac[data] = {
                                'from': from_,
                                'what_to_ignore': what_to_ignore,
                            }
                        elif 'org' in type_:
                            if data not in utils.supported_orgs:
                                self.print(f"Whitelisted org {data} is not supported in slips")
                                continue
                            # organizations dicts look something like this:
                            #  {'google': {'from':'dst',
                            #               'what_to_ignore': 'alerts'
                            #               'IPs': {'34.64.0.0/10': subnet}}
                            try:
                                # org already whitelisted, update info
                                whitelisted_orgs[data]['from'] = from_
                                whitelisted_orgs[data][
                                    'what_to_ignore'
                                ] = what_to_ignore
                            except KeyError:
                                # first time seeing this org
                                whitelisted_orgs[data] = {
                                    'from': from_,
                                    'what_to_ignore': what_to_ignore,
                                }

                        else:
                            self.print(f'{data} is not a valid {type_}.', 1, 0)
                    except:
                        self.print(
                            f'Line {line_number} in whitelist.conf is invalid. Skipping. '
                        )
        except FileNotFoundError:
            self.print(
                f"Can't find {self.whitelist_path}, using slips default whitelist.conf instead"
            )
            if self.whitelist_path != 'whitelist.conf':
                self.whitelist_path = 'whitelist.conf'
                self.read_whitelist()

        # store everything in the cache db because we'll be needing this info in the evidenceProcess
        __database__.set_whitelist('IPs', whitelisted_IPs)
        __database__.set_whitelist('domains', whitelisted_domains)
        __database__.set_whitelist('organizations', whitelisted_orgs)
        __database__.set_whitelist('mac', whitelisted_mac)

        return line_number

    def get_domains_of_flow(self, column_values):
        """Returns the domains of each ip (src and dst) that appeard in this flow"""
        # These separate lists, hold the domains that we should only check if they are SRC or DST. Not both
        domains_to_check_src = []
        domains_to_check_dst = []
        try:
            # self.print(f"IPData of src IP {column_values['saddr']}: {__database__.getIPData(column_values['saddr'])}")
            ip_data = __database__.getIPData(column_values['saddr'])
            if ip_data:
                sni_info = ip_data.get('SNI', [{}])[0]
                if sni_info:
                    domains_to_check_src.append(sni_info.get('server_name'))
        except (KeyError, TypeError):
            pass
        try:
            # self.print(f"DNS of src IP {column_values['saddr']}: {__database__.get_dns_resolution(column_values['saddr'])}")
            src_dns_domains = __database__.get_reverse_dns(
                column_values['saddr']
            )
            src_dns_domains = src_dns_domains.get('domains', [])
            for dns_domain in src_dns_domains:
                domains_to_check_src.append(dns_domain)
        except (KeyError, TypeError):
            pass
        try:
            # self.print(f"IPData of dst IP {column_values['daddr']}: {__database__.getIPData(column_values['daddr'])}")
            ip_data = __database__.getIPData(column_values['daddr'])
            if ip_data:
                sni_info = ip_data.get('SNI', [{}])[0]
                if sni_info:
                    domains_to_check_dst.append(sni_info.get('server_name'))
        except (KeyError, TypeError):
            pass
        return domains_to_check_dst, domains_to_check_src


    def is_ip_in_org(self, ip:str, org):
        """
        Check if the given ip belongs to the given org
        """
        org_subnets: dict = __database__.get_org_IPs(org)

        if '.' in ip:
            first_octet = ip.split('.')[0]
        elif ':' in ip:
            first_octet = ip.split(':')[0]
        else:
            return False
        ip_obj = ipaddress.ip_address(ip)
        # organization IPs are sorted by first octet for faster search
        for range in org_subnets.get(first_octet, []):
            if ip_obj in ipaddress.ip_network(range):
                return True
        return False

    def is_whitelisted_evidence(
            self, srcip, data, type_detection, description
        ) -> bool:
            """
            Checks if IP is whitelisted
            :param srcip: Src IP that generated the evidence
            :param data: This is what was detected in the evidence. (detection_info) can be ip, domain, tuple(ip:port:proto).
            :param type_detection: 'sip', 'dip', 'sport', 'dport', 'inTuple', 'outTuple', 'dstdomain'
            :param description: may contain IPs if the evidence is coming from portscan module
            """

            # self.print(f'Checking the whitelist of {srcip}: {data} {type_detection} {description} ')

            whitelist = __database__.get_all_whitelist()
            max_tries = 10
            # if this module is loaded before profilerProcess or before we're done processing the whitelist in general
            # the database won't return the whitelist
            # so we need to try several times until the db returns the populated whitelist
            # empty dicts evaluate to False
            while bool(whitelist) == False and max_tries != 0:
                # try max 10 times to get the whitelist, if it's still empty then it's not empty by mistake
                max_tries -= 1
                whitelist = __database__.get_all_whitelist()
            if max_tries is 0:
                # we tried 10 times to get the whitelist, it's probably empty.
                return False

            try:
                # Convert each list from str to dict
                whitelisted_IPs = json.loads(whitelist['IPs'])
            except (IndexError, KeyError):
                whitelisted_IPs = {}

            try:
                whitelisted_domains = json.loads(whitelist['domains'])
            except (IndexError, KeyError):
                whitelisted_domains = {}
            try:
                whitelisted_orgs = json.loads(whitelist['organizations'])
            except (IndexError, KeyError):
                whitelisted_orgs = {}
            try:
                whitelisted_mac = json.loads(whitelist['mac'])
            except (IndexError, KeyError):
                whitelisted_mac = {}

            # Set data type
            if 'domain' in type_detection:
                data_type = 'domain'
            elif 'outTuple' in type_detection:
                # for example: ip:port:proto
                data = data.split('-')[0]
                data_type = 'ip'

            elif 'dport' in type_detection:
                # is coming from portscan module
                try:
                    # data coming from portscan module contains the port and not the ip, we need to extract
                    # the ip from the description
                    ip_regex = r'[0-9]+.[0-9]+.[0-9]+.[0-9]+'
                    match = re.search(ip_regex, description)
                    if match:
                        data = match.group()
                        data_type = 'ip'
                    else:
                        # can't get the ip from the description!!
                        return False

                except (IndexError, ValueError):
                    # not coming from portscan module , data is a dport, do nothing
                    data_type = ''
                    pass
            else:
                # it's probably one of the following:  'sip', 'dip', 'sport'
                data_type = 'ip'

            # Check IPs
            if data_type == 'ip':
                # Check that the IP in the content of the alert is whitelisted
                # Was the evidence coming as a src or dst?
                ip = data
                is_srcip = type_detection in ('sip', 'srcip', 'sport', 'inTuple')
                is_dstip = type_detection in ('dip', 'dstip', 'dport', 'outTuple')
                if ip in whitelisted_IPs:
                    # Check if we should ignore src or dst alerts from this ip
                    # from_ can be: src, dst, both
                    # what_to_ignore can be: alerts or flows or both
                    from_ = whitelisted_IPs[ip]['from']
                    what_to_ignore = whitelisted_IPs[ip]['what_to_ignore']
                    ignore_alerts = (
                        'alerts' in what_to_ignore or 'both' in what_to_ignore
                    )

                    ignore_alerts_from_ip = (
                        ignore_alerts
                        and is_srcip
                        and ('src' in from_ or 'both' in from_)
                    )
                    ignore_alerts_to_ip = (
                        ignore_alerts
                        and is_dstip
                        and ('dst' in from_ or 'both' in from_)
                    )
                    if ignore_alerts_from_ip or ignore_alerts_to_ip:
                        # self.print(f'Whitelisting src IP {srcip} for evidence about {ip}, due to a connection related to {data} in {description}')
                        return True

                    # Now we know this ipv4 or ipv6 isn't whitelisted
                    # is the mac address of this ip whitelisted?
                    if whitelisted_mac:
                        # getthe mac addr of this ip from our db
                        # this mac can be src or dst mac, based on the type of ip (is_srcip or is_dstip)
                        mac = __database__.get_mac_addr_from_profile(
                            f'profile_{ip}'
                        )[0]
                        if mac and mac in list(whitelisted_mac.keys()):
                            # src or dst and
                            from_ = whitelisted_mac[mac]['from']
                            what_to_ignore = whitelisted_mac[mac]['what_to_ignore']
                            # do we want to whitelist alerts?
                            if (
                                'alerts' in what_to_ignore
                                or 'both' in what_to_ignore
                            ):
                                if is_srcip and (
                                    'src' in from_ or 'both' in from_
                                ):
                                    return True
                                if is_dstip and (
                                    'dst' in from_ or 'both' in from_
                                ):
                                    return True

            # Check domains
            if data_type == 'domain':
                is_srcdomain = type_detection in ('srcdomain')
                is_dstdomain = type_detection in ('dstdomain')
                domain = data
                # is domain in whitelisted domains?
                for domain_in_whitelist in whitelisted_domains:
                    # We go one by one so we can match substrings in the domains
                    sub_domain = domain[-len(domain_in_whitelist) :]
                    if domain_in_whitelist in sub_domain:
                        # Ignore src or dst
                        from_ = whitelisted_domains[sub_domain]['from']
                        # Ignore flows or alerts?
                        what_to_ignore = whitelisted_domains[sub_domain][
                            'what_to_ignore'
                        ]   # alerts or flows
                        ignore_alerts = (
                            'alerts' in what_to_ignore or 'both' in what_to_ignore
                        )
                        ignore_alerts_from_domain = (
                            ignore_alerts
                            and is_srcdomain
                            and ('src' in from_ or 'both' in from_)
                        )
                        ignore_alerts_to_domain = (
                            ignore_alerts
                            and is_dstdomain
                            and ('dst' in from_ or 'both' in from_)
                        )
                        if ignore_alerts_from_domain or ignore_alerts_to_domain:
                            # self.print(f'Whitelisting evidence about {domain_in_whitelist}, due to a connection related to {data} in {description}')
                            return True
            # Check orgs
            if whitelisted_orgs:
                is_src = type_detection in (
                    'sip',
                    'srcip',
                    'sport',
                    'inTuple',
                    'srcdomain',
                )
                is_dst = type_detection in (
                    'dip',
                    'dstip',
                    'dport',
                    'outTuple',
                    'dstdomain',
                )
                for org in whitelisted_orgs:
                    from_ = whitelisted_orgs[org]['from']
                    what_to_ignore = whitelisted_orgs[org]['what_to_ignore']
                    ignore_alerts = (
                        'alerts' in what_to_ignore or 'both' in what_to_ignore
                    )
                    ignore_alerts_from_org = (
                        ignore_alerts
                        and is_src
                        and ('src' in from_ or 'both' in from_)
                    )
                    ignore_alerts_to_org = (
                        ignore_alerts
                        and is_dst
                        and ('dst' in from_ or 'both' in from_)
                    )

                    # Check if the IP in the alert belongs to a whitelisted organization
                    if data_type == 'ip':
                        ip = data
                        if ignore_alerts_from_org or ignore_alerts_to_org:
                            # Method 1: using asn
                            # Check if the IP in the content of the alert has ASN info in the db
                            ip_data = __database__.getIPData(ip)
                            if ip_data:
                                ip_asn = ip_data.get('asn', {'asnorg': ''})[
                                    'asnorg'
                                ]
                                org_asn = json.loads(
                                    __database__.get_org_info(org, 'asn')
                                )
                                # make sure the asn field contains a value
                                if ip_asn not in ('', 'Unknown') and (
                                    org.lower() in ip_asn.lower()
                                    or ip_asn in org_asn
                                ):
                                    # this ip belongs to a whitelisted org, ignore alert
                                    # self.print(f'Whitelisting evidence sent by {srcip} about {ip} due to ASN of {ip}
                                    # related to {org}. {data} in {description}')
                                    return True

                        # Method 2 using the organization's list of ips
                        # ip doesn't have asn info, search in the list of organization IPs
                        try:
                            if self.is_ip_in_org(ip, org):
                                # self.print(f'Whitelisting evidence sent by {srcip} about {ip},
                                # due to {ip} being in the range of {org}. {data} in {description}')
                                return True
                        except (KeyError, TypeError):
                            # comes here if the whitelisted org doesn't have info in slips/organizations_info (not a famous org)
                            # and ip doesn't have asn info.
                            pass

                    if data_type == 'domain':
                        flow_domain = data
                        # Method 3 Check if the domains of this flow belong to this org domains
                        try:
                            if self.is_domain_in_org(flow_domain, org):
                                return True
                        except (KeyError, TypeError):
                            # comes here if the whitelisted org doesn't have domains in slips/organizations_info (not a famous org)
                            # and ip doesn't have asn info.
                            # so we don't know how to link this ip to the whitelisted org!
                            pass
            return False

    def load_org_asn(self, org) -> list:
        """
        Reads the specified org's asn from slips_files/organizations_info and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's asn
        """
        try:
            # Each file is named after the organization's name followed by _asn
            org_asn = []
            asn_info_file = os.path.join(self.org_info_path, f'{org}_asn')
            with open(asn_info_file, 'r') as f:
                while line := f.readline():
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace('\n', '').strip()
                    # Read all as upper
                    org_asn.append(line.upper())

        except (FileNotFoundError, IOError):
            # theres no slips_files/organizations_info/{org}_asn for this org
            # see if the org has asn cached in our db
            asn_cache = __database__.get_asn_cache()
            org_asn = []
            for asn in asn_cache:
                if org in asn.lower():
                    org_asn.append(org)

        __database__.set_org_info(org, json.dumps(org_asn), 'asn')
        return org_asn

    def load_org_domains(self, org):
        """
        Reads the specified org's domains from slips_files/organizations_info and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's domains
        """
        try:
            domains = []
            # Each file is named after the organization's name followed by _domains
            domain_info_file = os.path.join(self.org_info_path, f'{org}_domains')
            with open(domain_info_file, 'r') as f:
                while line := f.readline():
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace('\n', '').strip()
                    domains.append(line.lower())
                    # Store the IPs of this org
        except (FileNotFoundError, IOError):
            return False

        __database__.set_org_info(org, json.dumps(domains), 'domains')
        return domains

    def load_org_IPs(self, org):
        """
        Reads the specified org's info from slips_files/organizations_info and stores the info in the database
        if there's no file for this org, it get the IP ranges from asnlookup.com
        org: 'google', 'facebook', 'twitter', etc...
        returns a list of this organization's subnets
        """
        if org not in utils.supported_orgs:
            return

        org_info_file = os.path.join(self.org_info_path, org)
        try:
            # Each file is named after the organization's name
            # Each line of the file contains an ip range, for example: 34.64.0.0/10
            org_subnets = {}
            with open(org_info_file, 'r') as f:
                line = f.readline()
                while line:
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace('\n', '').strip()
                    try:
                        # make sure this line is a valid network
                        ipaddress.ip_network(line)
                    except ValueError:
                        # not a valid line, ignore it
                        continue

                    if '.' in line:
                        first_octet = line.split('.')[0]
                    elif ':' in line:
                        first_octet = line.split(':')[0]
                    else:
                        # not ipv4 or opv6
                        continue
                    try:
                        org_subnets[first_octet].append(line)
                    except KeyError:
                        org_subnets[first_octet] = [line]

                    line = f.readline()

        except (FileNotFoundError, IOError):
            # there's no slips_files/organizations_info/{org} for this org
            return

        # Store the IPs of this org
        __database__.set_org_info(org, json.dumps(org_subnets), 'IPs')
        return org_subnets

