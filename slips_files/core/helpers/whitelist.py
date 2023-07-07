import json
import ipaddress
import validators
from slips_files.common.imports import *
import tld
import os


class Whitelist:
    def __init__(self, output_queue, db):
        self.name = 'whitelist'
        self.output_queue = output_queue
        self.read_configuration()
        self.org_info_path = 'slips_files/organizations_info/'
        self.ignored_flow_types = ('arp')
        self.db = db

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
        self.output_queue.put(f'{levels}|{self.name}|{text}')

    def read_configuration(self):
        conf = ConfigParser()
        self.whitelist_path = conf.whitelist_path()

    def is_whitelisted_asn(self, ip, org):
        ip_data = self.db.getIPData(ip)
        try:
            ip_asn = ip_data['asn']['asnorg']
            org_asn = json.loads(self.db.get_org_info(org, 'asn'))
            if (
                ip_asn
                and ip_asn != 'Unknown'
                and (org.lower() in ip_asn.lower() or ip_asn in org_asn)
            ):
                # this ip belongs to a whitelisted org, ignore flow
                # self.print(f"The ASN {ip_asn} of IP {ip} "
                #            f"is in the values of org {org}. Whitelisted.")
                return True
        except (KeyError, TypeError):
            # No asn data for src ip
            pass

    def is_ignored_flow_type(self, flow_type) -> bool:
        """
        Function reduce the number of checks we make if we don't need to check this type of flow
        """
        if flow_type in self.ignored_flow_types:
            return True


    def is_whitelisted_domain_in_flow(
            self, whitelisted_domain, direction, domains_of_flow, ignore_type
    ):
        """
        Given the domain of a flow, and a whitelisted domain,
        this function checks any of the flow domains
        is a subdomain or the same domain as the whitelisted domain

        :param whitelisted_domain: the domain we want to check if it exists in the domains_of_flow
        :param ignore_type: alerts or flows or both
        :param direction: src or dst or both
        :param domains_of_flow: src domains of the src IP of the flow,
                                or dst domains of the dst IP of the flow
        """
        whitelisted_domains = self.db.get_whitelist('domains')
        if not whitelisted_domains:
            return False

        # do we wanna whitelist flows coming from or going to this domain or both?
        from_ = whitelisted_domains[whitelisted_domain]['from']
        # Now check the domains of the src IP
        if direction in from_ or 'both' in from_:
            what_to_ignore = whitelisted_domains[whitelisted_domain]['what_to_ignore']

            for domain_to_check in domains_of_flow:
                main_domain = domain_to_check[-len(whitelisted_domain) :]
                if whitelisted_domain in main_domain:
                    # We can ignore flows or alerts, what is it?
                    if (
                        ignore_type in what_to_ignore
                        or 'both' in what_to_ignore
                    ):
                        return True
        return False

    def is_whitelisted_domain(self, domain_to_check, saddr, daddr, ignore_type):
        """
        Used only when checking whitelisted flows
        (aka domains associated with the src or dstip of a flow)
        :param domain_to_check: the domain we want to know if whitelisted or not
        :param saddr: saddr of the flow we're checking
        :param daddr: daddr of the flow we're checking
        :param ignore_type: what did the user whitelist? alerts or flows or both
        """

        whitelisted_domains = self.db.get_whitelist('domains')
        if not whitelisted_domains:
            return False

        # get the domains of this flow
        (
            dst_domains_of_flow,
            src_domains_of_flow,
        ) = self.get_domains_of_flow(saddr, daddr)

        # self.print(f'Domains to check from flow: {domains_to_check}, {domains_to_check_dst} {domains_to_check_src}')
        # Go through each whitelisted domain and check if what arrived is there
        for whitelisted_domain in list(whitelisted_domains.keys()):
            what_to_ignore = whitelisted_domains[whitelisted_domain]['what_to_ignore']
            # Here we iterate over all the domains to check if we can find
            # subdomains. If slack.com was whitelisted, then test.slack.com
            # should be ignored too. But not 'slack.com.test'
            main_domain = domain_to_check[-len(whitelisted_domain) :]
            if whitelisted_domain in main_domain:
                # We can ignore flows or alerts, what is it?
                if (
                    ignore_type in what_to_ignore
                    or 'both' in what_to_ignore
                ):
                    # self.print(f'Whitelisting the domain {domain_to_check} due to whitelist of {domain_to_check}')
                    return True


            if self.is_whitelisted_domain_in_flow(whitelisted_domain, 'src', src_domains_of_flow, ignore_type):
                # self.print(f"Whitelisting the domain {domain_to_check} because is related"
                #            f" to domain {domain_to_check} of dst IP {daddr}")
                return True

            if self.is_whitelisted_domain_in_flow(whitelisted_domain, 'dst', dst_domains_of_flow, ignore_type):
                # self.print(f"Whitelisting the domain {domain_to_check} because is"
                #            f"related to domain {domain_to_check} of src IP {saddr}")
                return True
        return False


    def is_whitelisted_flow(self, flow) -> bool:
        """
        Checks if the src IP or dst IP or domain or organization of this flow is whitelisted.
        """
        saddr = flow.saddr
        daddr = flow.daddr
        flow_type = flow.type_
        # get the domains of the IPs this flow
        (
            domains_to_check_dst,
            domains_to_check_src,
        ) = self.get_domains_of_flow(saddr, daddr)
        # check if we have whitelisted domains

        # first get the domains of the flows we ewnt to check if whitelisted
        # Domain names are stored in different zeek files using different names.
        # Try to get the domain from each file.
        domains_to_check = []
        if flow_type == 'ssl':
            domains_to_check.append(flow.server_name)
        elif flow_type == 'http':
            domains_to_check.append(flow.host)
        elif flow_type == 'ssl':
            domains_to_check.append(flow.subject.replace(
                'CN=', ''
            ))
        elif flow_type == 'dns':
            domains_to_check.append(flow.query)


        for domain in domains_to_check:
            if self.is_whitelisted_domain(domain, saddr, daddr, 'flows'):
                return True



        if whitelisted_IPs := self.db.get_whitelist('IPs'):
            # self.print('Check the IPs')
            # Check if the IPs are whitelisted
            ips_to_whitelist = list(whitelisted_IPs.keys())

            if saddr in ips_to_whitelist:
                # The flow has the src IP to whitelist
                from_ = whitelisted_IPs[saddr]['from']
                what_to_ignore = whitelisted_IPs[saddr]['what_to_ignore']
                if ('src' in from_ or 'both' in from_) and (
                        self.should_ignore_flows(what_to_ignore)
                ):
                    # self.print(f"Whitelisting the src IP {column_values['saddr']}")
                    return True

            if daddr in ips_to_whitelist:   # should be if and not elif
                # The flow has the dst IP to whitelist
                from_ = whitelisted_IPs[daddr]['from']
                what_to_ignore = whitelisted_IPs[daddr]['what_to_ignore']
                if ('dst' in from_ or 'both' in from_) and (
                    self.should_ignore_flows(what_to_ignore)
                ):
                    # self.print(f"Whitelisting the dst IP {column_values['daddr']}")
                    return True

            if flow_type == 'dns':
                # check all answers
                for answer in flow.answers:
                    if answer in ips_to_whitelist:
                        # #TODO the direction doesn't matter here right?
                        # direction = whitelisted_IPs[daddr]['from']
                        what_to_ignore = whitelisted_IPs[answer]['what_to_ignore']
                        if self.should_ignore_flows(what_to_ignore):
                            # self.print(f"Whitelisting the IP {answer} due to its presence in a dns answer")
                            return True


        if whitelisted_macs := self.db.get_whitelist('mac'):
            # try to get the mac address of the current flow
            src_mac = flow.smac if hasattr(flow, 'smac') else False

            if not src_mac:
                if src_mac := self.db.get_mac_addr_from_profile(
                    f'profile_{saddr}'
                ):
                    src_mac = src_mac[0]

            if src_mac and src_mac in list(whitelisted_macs.keys()):
                # the src mac of this flow is whitelisted, but which direction?
                from_ = whitelisted_macs[src_mac]['from']
                what_to_ignore = whitelisted_macs[src_mac]['what_to_ignore']

                if (
                    ('src' in from_ or 'both' in from_)
                    and
                    self.should_ignore_flows(what_to_ignore)
                ):
                    # self.print(f"The source MAC of this flow {src_mac} is whitelisted")
                    return True

            dst_mac = flow.dmac if hasattr(flow, 'smac') else False
            if dst_mac and dst_mac in list(whitelisted_macs.keys()):
                # the dst mac of this flow is whitelisted, but which direction?
                from_ = whitelisted_macs[dst_mac]['from']
                what_to_ignore = whitelisted_macs[dst_mac]['what_to_ignore']

                if (
                    ('dst' in from_ or 'both' in from_)
                    and
                    self.should_ignore_flows(what_to_ignore)
                ):
                    # self.print(f"The dst MAC of this flow {dst_mac} is whitelisted")
                    return True

        if self.is_ignored_flow_type(flow_type):
            return False

        if whitelisted_orgs := self.db.get_whitelist('organizations'):
            # self.print('Check if the organization is whitelisted')
            # Check if IP belongs to a whitelisted organization range
            # Check if the ASN of this IP is any of these organizations

            for org in whitelisted_orgs:
                from_ = whitelisted_orgs[org]['from']  # src or dst or both
                what_to_ignore = whitelisted_orgs[org][
                    'what_to_ignore'
                ]  # flows, alerts or both
                # self.print(f'Checking {org}, from:{from_} type {what_to_ignore}')

                if self.should_ignore_flows(what_to_ignore):
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
                                # self.print(f"The src IP {saddr} is in the ranges of org {org}. Whitelisted.")
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
                            if self.is_ip_in_org(flow.daddr, org):
                                # self.print(f"The dst IP {column_values['daddr']} "
                                #            f"is in the network range of org {org}. Whitelisted.")
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
        try:
            org_domains = json.loads(
                self.db.get_org_info(org, 'domains')
            )
            if org in domain:
                # self.print(f"The domain of this flow ({domain}) belongs to the domains of {org}")
                return True

            try:
                flow_TLD = tld.get_tld(domain, as_object=True)
            except tld.exceptions.TldBadUrl:
                flow_TLD = domain.split('.')[-1]

            for org_domain in org_domains:
                try:
                    org_domain_TLD = tld.get_tld(org_domain, as_object=True)
                except tld.exceptions.TldBadUrl:
                    org_domain_TLD = org_domain.split('.')[-1]

                # make sure the 2 domains have the same same top level domain
                if flow_TLD != org_domain_TLD:
                    continue

                # match subdomains too
                # if org has org.com, and the flow_domain is xyz.org.com whitelist it
                if org_domain in domain:
                    # self.print(f"The src domain of this flow ({domain}) is "
                    #            f"a subdomain of {org} domain: {org_domain}")
                    return True
                # if org has xyz.org.com, and the flow_domain is org.com whitelist it
                if domain in org_domain:
                    # self.print(f"The domain of {org} ({org_domain}) is a subdomain of "
                    #            f"this flow domain ({domain})")
                    return True
        except (KeyError, TypeError):
            # comes here if the whitelisted org doesn't have domains in slips/organizations_info (not a famous org)
            # and ip doesn't have asn info.
            # so we don't know how to link this ip to the whitelisted org!
            pass

    def read_whitelist(self):
        """Reads the content of whitelist.conf and stores information about each ip/org/domain in the database"""

        # since this function can be run when the user modifies whitelist.conf
        # we need to check if the dicts are already there
        whitelisted_IPs = self.db.get_whitelist('IPs')
        whitelisted_domains = self.db.get_whitelist('domains')
        whitelisted_orgs = self.db.get_whitelist('organizations')
        whitelisted_mac = self.db.get_whitelist('mac')
        # Process lines after comments
        line_number = 0
        try:
            with open(self.whitelist_path) as whitelist:
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
                    except Exception:
                        self.print(
                            f'Line {line_number} in whitelist.conf is invalid. Skipping. '
                        )
        except FileNotFoundError:
            self.print(
                f"Can't find {self.whitelist_path}, using slips default whitelist.conf instead"
            )
            if self.whitelist_path != 'config/whitelist.conf':
                self.whitelist_path = 'config/whitelist.conf'
                self.read_whitelist()

        # store everything in the cache db because we'll be needing this info in the evidenceProcess
        self.db.set_whitelist('IPs', whitelisted_IPs)
        self.db.set_whitelist('domains', whitelisted_domains)
        self.db.set_whitelist('organizations', whitelisted_orgs)
        self.db.set_whitelist('mac', whitelisted_mac)

        return whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_mac

    def get_domains_of_flow(self, saddr, daddr):
        """
        Returns the domains of each ip (src and dst) that appeard in this flow
        """
        # These separate lists, hold the domains that we should only
        # check if they are SRC or DST. Not both
        domains_to_check_src = []
        domains_to_check_dst = []
        try:
            if ip_data := self.db.getIPData(saddr):
                if sni_info := ip_data.get('SNI', [{}])[0]:
                    domains_to_check_src.append(sni_info.get('server_name', ''))
        except (KeyError, TypeError):
            pass
        try:
            # self.print(f"DNS of src IP {column_values['saddr']}: {self.db.get_dns_resolution(column_values['saddr'])}")
            src_dns_domains = self.db.get_dns_resolution(saddr)
            src_dns_domains = src_dns_domains.get('domains', [])
            domains_to_check_src.extend(iter(src_dns_domains))
        except (KeyError, TypeError):
            pass
        try:
            if ip_data := self.db.getIPData(daddr):
                if sni_info := ip_data.get('SNI', [{}])[0]:
                    domains_to_check_dst.append(sni_info.get('server_name'))
        except (KeyError, TypeError):
            pass

        try:
            # self.print(f"DNS of dst IP {column_values['daddr']}: {self.db.get_dns_resolution(column_values['daddr'])}")
            dst_dns_domains = self.db.get_dns_resolution(daddr)
            dst_dns_domains = dst_dns_domains.get('domains', [])
            domains_to_check_dst.extend(iter(dst_dns_domains))
        except (KeyError, TypeError):
            pass

        return domains_to_check_dst, domains_to_check_src

    def is_ip_in_org(self, ip:str, org):
        """
        Check if the given ip belongs to the given org
        """
        try:
            org_subnets: dict = self.db.get_org_IPs(org)

            first_octet:str = utils.get_first_octet(ip)
            if not first_octet:
                return
            ip_obj = ipaddress.ip_address(ip)
            # organization IPs are sorted by first octet for faster search
            for range in org_subnets.get(first_octet, []):
                if ip_obj in ipaddress.ip_network(range):
                    return True
        except (KeyError, TypeError):
            # comes here if the whitelisted org doesn't have
            # info in slips/organizations_info (not a famous org)
            # and ip doesn't have asn info.
            pass
        return False
    
    def profile_has_whitelisted_mac(
            self, profile_ip, whitelisted_macs, is_srcip, is_dstip
    ) -> bool:
        """
        Checks for alerts whitelist
        """
        mac = self.db.get_mac_addr_from_profile(
            f'profile_{profile_ip}'
        )
        
        if not mac:
            # we have no mac for this profile
            return False

        mac = mac[0]
        if mac in list(whitelisted_macs.keys()):
            # src or dst and
            from_ = whitelisted_macs[mac]['from']
            what_to_ignore = whitelisted_macs[mac]['what_to_ignore']
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

    def is_ip_asn_in_org_asn(self, ip, org):
        """
        returns true if the ASN of the given IP is listed in the ASNs of the given org ASNs
        """
        # Check if the IP in the content of the alert has ASN info in the db
        ip_data = self.db.getIPData(ip)
        if not ip_data:
            return
        try:
            ip_asn = ip_data['asn']['number']
        except KeyError:
            return

        org_asn: list = json.loads(self.db.get_org_info(org, 'asn'))

        # make sure the asn field contains a value
        if (
            org.lower() in ip_asn.lower()
            or ip_asn in org_asn
        ):
            # this ip belongs to a whitelisted org, ignore alert
            # self.print(f'Whitelisting evidence sent by {srcip} about {ip} due to ASN of {ip}
            # related to {org}. {data} in {description}')
            return True

    def is_srcip(self, attacker_direction):
        return attacker_direction in ('sip', 'srcip', 'sport', 'inTuple')

    def is_dstip(self, attacker_direction):
        return attacker_direction in ('dip', 'dstip', 'dport', 'outTuple')

    def should_ignore_from(self, direction) -> bool:
        """
        Returns true if the user wants to whitelist alerts/flows from this source(ip, org, mac, etc)
        """
        return ('src' in direction or 'both' in direction)

    def should_ignore_to(self, direction) -> bool:
        """
        Returns true if the user wants to whitelist alerts/flows to this source(ip, org, mac, etc)
        """
        return ('dst' in direction or 'both' in direction)

    def should_ignore_alerts(self, what_to_ignore)-> bool:
        """
        returns true we if the user wants to ignore alerts
        """
        return 'alerts' in what_to_ignore or 'both' in what_to_ignore

    def should_ignore_flows(self, what_to_ignore)-> bool:
        """
        returns true we if the user wants to ignore alerts
        """
        return 'flows' in what_to_ignore or 'both' in what_to_ignore

    def parse_whitelist(self, whitelist):
        """
        returns a tuple with whitelisted IPs, domains, orgs and MACs
        """
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
            whitelisted_macs = json.loads(whitelist['mac'])
        except (IndexError, KeyError):
            whitelisted_macs = {}
        return whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_macs


    def is_whitelisted_evidence(
            self, srcip, attacker, attacker_direction, description, victim
        ) -> bool:
        """
        Checks if IP is whitelisted
        :param srcip: Src IP that generated the evidence
        :param attacker: This is what was detected in the evidence. (attacker) can be ip, domain, tuple(ip:port:proto).
        :param attacker_direction: this is the type of the attacker param. 'sip', 'dip', 'sport', 'dport', 'inTuple',
        'outTuple', 'dstdomain'
        :param description: may contain IPs if the evidence is coming from portscan module
        :param victim: ip of the victim (will either be the saddr, the daddr, or '' in case of scans)
        """

        # self.print(f'Checking the whitelist of {srcip}: {data} {attacker_direction} {description} ')

        whitelist = self.db.get_all_whitelist()
        max_tries = 10
            # if this module is loaded before profilerProcess or before we're done processing the whitelist in general
            # the database won't return the whitelist
            # so we need to try several times until the db returns the populated whitelist
            # empty dicts evaluate to False
        while not bool(whitelist) and max_tries != 0:
            # try max 10 times to get the whitelist, if it's still empty then it's not empty by mistake
            max_tries -= 1
            whitelist = self.db.get_all_whitelist()
        if max_tries == 0:
            # we tried 10 times to get the whitelist, it's probably empty.
            return False

        if self.check_whitelisted_attacker(attacker, attacker_direction):
            return True

        if self.check_whitelisted_victim(victim, srcip):
            return True

    def check_whitelisted_victim(self, victim, srcip):
        if not victim:
            return False

        whitelist = self.db.get_all_whitelist()
        whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_macs = self.parse_whitelist(whitelist)

        victim = victim.strip()
        victim_type = utils.detect_data_type(victim)

        if victim_type == 'ip':
            ip = victim
            is_srcip = True if srcip in victim else False
            if self.is_ip_whitelisted(ip, is_srcip):
                return True

        elif victim_type == 'domain':
            # the domain can never be a source here
            if self.is_domain_whitelisted(victim, 'dstdomain'):
                return True

        direction = 'src' if srcip in victim else 'dst'
        if (
                whitelisted_orgs
                and self.is_part_of_a_whitelisted_org(victim, victim_type, direction)
        ):
            return True


    def check_whitelisted_attacker(self, attacker, attacker_direction):

        whitelist = self.db.get_all_whitelist()
        whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_macs = self.parse_whitelist(whitelist)

        # Set attacker type
        if 'domain' in attacker_direction:
            attacker_type = 'domain'
        elif 'outTuple' in attacker_direction:
            # for example: ip:port:proto
            attacker = attacker.split('-')[0]
            attacker_type = 'ip'
        else:
            # it's probably one of the following:  'sip', 'dip', 'sport'
            attacker_type = 'ip'

        # Check IPs
        if attacker_type == 'domain':
            if self.is_domain_whitelisted(attacker, attacker_direction):
                return True

        elif attacker_type == 'ip':
            # Check that the IP in the content of the alert is whitelisted
            # Was the evidence coming as a src or dst?
            ip = attacker
            is_srcip = self.is_srcip(attacker_direction)
            # is_dstip = self.is_dstip(attacker_direction)
            if self.is_ip_whitelisted(ip, is_srcip):
                return True

        # Check orgs
        if (
                whitelisted_orgs
                and self.is_part_of_a_whitelisted_org(attacker, attacker_type, attacker_direction)
        ):
               return True

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
            asn_cache: dict = self.db.get_asn_cache()
            org_asn = []
            # asn_cache is a dict sorted by first octet
            for octet, range_info in asn_cache.items:
                # range_info is a serialized dict of ranges
                range_info = json.loads(range_info)
                for range, asn_info in range_info.items():
                    # we have the asn of this given org cached
                    if org in asn_info['org'].lower():
                        org_asn.append(org)

        self.db.set_org_info(org, json.dumps(org_asn), 'asn')
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

        self.db.set_org_info(org, json.dumps(domains), 'domains')
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
                while line := f.readline():
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace('\n', '').strip()
                    try:
                        # make sure this line is a valid network
                        ipaddress.ip_network(line)
                    except ValueError:
                        # not a valid line, ignore it
                        continue

                    first_octet = utils.get_first_octet(line)
                    if not first_octet:
                        line = f.readline()
                        continue

                    try:
                        org_subnets[first_octet].append(line)
                    except KeyError:
                        org_subnets[first_octet] = [line]

        except (FileNotFoundError, IOError):
            # there's no slips_files/organizations_info/{org} for this org
            return

        # Store the IPs of this org
        self.db.set_org_info(org, json.dumps(org_subnets), 'IPs')
        return org_subnets

    def is_ip_whitelisted(self, ip: str, is_srcip: bool):
        """
        checks the given IP in the whitelisted IPs read from whitelist.conf
        """
        whitelist = self.db.get_all_whitelist()
        whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_macs = self.parse_whitelist(whitelist)

        is_dstip = not is_srcip
        if ip in whitelisted_IPs:
            # Check if we should ignore src or dst alerts from this ip
            # from_ can be: src, dst, both
            # what_to_ignore can be: alerts or flows or both
            direction = whitelisted_IPs[ip]['from']
            what_to_ignore = whitelisted_IPs[ip]['what_to_ignore']
            ignore_alerts = self.should_ignore_alerts(what_to_ignore)

            ignore_alerts_from_ip = (
                ignore_alerts
                and is_srcip
                and self.should_ignore_from(direction)
            )
            ignore_alerts_to_ip = (
                ignore_alerts
                and is_dstip
                and self.should_ignore_to(direction)
            )
            if ignore_alerts_from_ip or ignore_alerts_to_ip:
                # self.print(f'Whitelisting src IP {srcip} for evidence'
                #            f' about {ip}, due to a connection related to {data} '
                #            f'in {description}')
                return True

                # Now we know this ipv4 or ipv6 isn't whitelisted
                # is the mac address of this ip whitelisted?
            if whitelisted_macs and self.profile_has_whitelisted_mac(
                ip, whitelisted_macs, is_srcip, is_dstip
            ):
                return True

    def is_domain_whitelisted(self, domain: str, direction: str):
        """
        :param direction: can be either srcdomain or dstdomain
        """
        # todo differentiate between this and is_whitelisted_Domain()
        is_srcdomain = direction in ('srcdomain')
        is_dstdomain = direction in ('dstdomain')

        # extract the top level domain
        try:
            domain = tld.get_fld(domain, fix_protocol=True)
        except (tld.exceptions.TldBadUrl, tld.exceptions.TldDomainNotFound):
            for str_ in ('http://', 'https://','www'):
                domain = domain.replace(str_, "")

        whitelist = self.db.get_all_whitelist()
        whitelisted_domains = self.parse_whitelist(whitelist)[1]

        # is domain in whitelisted domains?
        for domain_in_whitelist in whitelisted_domains:
            # We go one by one so we can match substrings in the domains
            sub_domain = domain[-len(domain_in_whitelist) :]
            if domain_in_whitelist in sub_domain:
                # Ignore src or dst
                direction = whitelisted_domains[sub_domain]['from']
                # Ignore flows or alerts?
                what_to_ignore = whitelisted_domains[sub_domain][
                    'what_to_ignore'
                ]   # alerts or flows
                ignore_alerts = self.should_ignore_alerts(what_to_ignore)
                ignore_alerts_from_domain = (
                    ignore_alerts
                    and is_srcdomain
                    and self.should_ignore_from(direction)
                )
                ignore_alerts_to_domain = (
                    ignore_alerts
                    and is_dstdomain
                    and self.should_ignore_to(direction)
                )
                if ignore_alerts_from_domain or ignore_alerts_to_domain:
                    # self.print(f'Whitelisting evidence about '
                    #            f'{domain_in_whitelist}, due to a connection '
                    #            f'related to {data} in {description}')
                    return True

        if self.db.is_whitelisted_tranco_domain(domain):
            # tranco list contains the top 10k known benign domains
            # https://tranco-list.eu/list/X5QNN/1000000
            return True

    def is_part_of_a_whitelisted_org(self, ioc, ioc_type, direction):
        """
        :param ioc: can be ip or domain
        :param direction: can src or dst ip or domain
        :param ioc: can be ip or domain
        """
        is_src = self.is_srcip(direction) or direction in 'srcdomain'
        is_dst = self.is_dstip(direction) or direction in 'dstdomain'

        whitelist = self.db.get_all_whitelist()
        whitelisted_orgs = self.parse_whitelist(whitelist)[2]

        for org in whitelisted_orgs:
            from_ = whitelisted_orgs[org]['from']
            what_to_ignore = whitelisted_orgs[org]['what_to_ignore']
            ignore_alerts = self.should_ignore_alerts(what_to_ignore)
            ignore_alerts_from_org = (
                ignore_alerts
                and is_src
                and self.should_ignore_from(from_)
            )
            ignore_alerts_to_org = (
                ignore_alerts
                and is_dst
                and self.should_ignore_to(from_)
            )

            # Check if the IP in the alert belongs to a whitelisted organization
            if ioc_type == 'domain':
                # Method 3 Check if the domains of this flow belong to this org domains
                if self.is_domain_in_org(ioc, org):
                    return True

            elif ioc_type == 'ip':
                if ignore_alerts_from_org or ignore_alerts_to_org:
                    # Method 1: using asn
                    self.is_ip_asn_in_org_asn(ioc, org)

                    # Method 2 using the organization's list of ips
                    # ip doesn't have asn info, search in the list of organization IPs
                    if self.is_ip_in_org(ioc, org):
                        # self.print(f'Whitelisting evidence sent by {srcip} about {ip},'
                        #            f'due to {ip} being in the range of {org}. {data} in {description}')
                        return True
