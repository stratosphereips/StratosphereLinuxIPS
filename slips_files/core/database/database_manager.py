from slips_files.core.database.redis_db.database import RedisDB
from slips_files.core.database.sqlite_db.database import SQLiteDB


class DBManager:
    """
    This class will be calling methods from the appropriate db.
    each method added to any of the dbs should have a
    handler in here
    """
    _obj = None

    def __new__(cls,  *args, **kwargs):
        if cls._obj is None or not isinstance(cls._obj, cls):
            # these args will only be passed by slips.py
            # the rest of the modules can create an obj of this class without these args,
            # and will get the same obj instatiated by slips.py
            output_dir, output_queue, redis_port = args[0], args[1], args[2]
            cls._obj = super().__new__(DBManager)
            cls.sqlite = SQLiteDB(output_dir)
            cls.rdb = RedisDB(redis_port, output_queue)

        return cls._obj

    def publish(self, *args):
        return self.rdb.publish(*args)

    def subscribe(self, *args):
        return self.rdb.subscribe(*args)

    def publish_stop(self, *args):
        return self.rdb.publish_stop(*args)

    def get_message(self, *args, **kwargs):
        return self.rdb.get_message(*args, **kwargs)

    def print(self, *args, **kwargs):
        return self.rdb.print(*args, **kwargs)

    def getIPData(self, *args):
        return self.rdb.getIPData(*args)

    def set_new_ip(self, *args):
        return self.rdb.set_new_ip(*args)

    def ask_for_ip_info(self, *args, **kwargs):
        return self.rdb.ask_for_ip_info(*args, **kwargs)

    def update_times_contacted(self, *args):
        return self.rdb.update_times_contacted(*args)

    def update_ip_info(self, *args):
        return self.rdb.update_ip_info(*args)

    def getSlipsInternalTime(self, *args):
        return self.rdb.getSlipsInternalTime(*args)

    def get_equivalent_tws(self, *args):
        return self.rdb.get_equivalent_tws(*args)

    def set_local_network(self, *args):
        return self.rdb.set_local_network(*args)

    def get_local_network(self, *args):
        return self.rdb.get_local_network(*args)

    def get_label_count(self, *args):
        return self.rdb.get_label_count(*args)

    def get_disabled_modules(self, *args):
        return self.rdb.get_disabled_modules(*args)

    def set_input_metadata(self, *args):
        return self.rdb.set_input_metadata(*args)

    def get_zeek_output_dir(self, *args):
        return self.rdb.get_zeek_output_dir(*args)

    def get_input_type(self, *args):
        return self.rdb.get_input_type(*args)

    def get_output_dir(self, *args):
        return self.rdb.get_output_dir(*args)

    def setInfoForIPs(self, *args):
        return self.rdb.setInfoForIPs(*args)

    def get_p2p_reports_about_ip(self, *args):
        return self.rdb.get_p2p_reports_about_ip(*args)

    def store_p2p_report(self, *args):
        return self.rdb.store_p2p_report(*args)

    def get_dns_resolution(self, *args):
        return self.rdb.get_dns_resolution(*args)

    def is_ip_resolved(self, *args):
        return self.rdb.is_ip_resolved(*args)

    def delete_dns_resolution(self, *args):
        return self.rdb.delete_dns_resolution(*args)

    def should_store_resolution(self, *args):
        return self.rdb.should_store_resolution(*args)

    def set_dns_resolution(self, *args):
        return self.rdb.set_dns_resolution(*args)

    def set_domain_resolution(self, *args):
        return self.rdb.set_domain_resolution(*args)

    def get_redis_server_PID(self, *args):
        return self.rdb.get_redis_server_PID(*args)

    def set_slips_mode(self, *args):
        return self.rdb.set_slips_mode(*args)

    def get_slips_mode(self, *args):
        return self.rdb.get_slips_mode(*args)

    def get_modified_ips_in_the_last_tw(self, *args):
        return self.rdb.get_modified_ips_in_the_last_tw(*args)

    def is_connection_error_logged(self, *args):
        return self.rdb.is_connection_error_logged(*args)

    def mark_connection_error_as_logged(self, *args):
        return self.rdb.mark_connection_error_as_logged(*args)

    def was_ip_seen_in_connlog_before(self, *args):
        return self.rdb.was_ip_seen_in_connlog_before(*args)

    def mark_srcip_as_seen_in_connlog(self, *args):
        return self.rdb.mark_srcip_as_seen_in_connlog(*args)

    def is_gw_mac(self, *args):
        return self.rdb.is_gw_mac(*args)

    def get_ip_of_mac(self, *args):
        return self.rdb.get_ip_of_mac(*args)

    def get_modified_tw(self, *args):
        return self.rdb.get_modified_tw(*args)

    def get_field_separator(self, *args):
        return self.rdb.get_field_separator(*args)

    def store_tranco_whitelisted_domain(self, *args):
        return self.rdb.store_tranco_whitelisted_domain(*args)

    def is_whitelisted_tranco_domain(self, *args):
        return self.rdb.is_whitelisted_tranco_domain(*args)

    def set_growing_zeek_dir(self, *args):
        return self.rdb.set_growing_zeek_dir(*args)

    def is_growing_zeek_dir(self, *args):
        return self.rdb.is_growing_zeek_dir(*args)

    def get_ip_identification(self, *args):
        return self.rdb.get_ip_identification(*args)

    def get_multiaddr(self, *args):
        return self.rdb.get_multiaddr(*args)

    def get_labels(self, *args):
        return self.rdb.get_labels(*args)

    def set_port_info(self, *args):
        return self.rdb.set_port_info(*args)

    def get_port_info(self, *args):
        return self.rdb.get_port_info(*args)

    def set_ftp_port(self, *args):
        return self.rdb.set_ftp_port(*args)

    def is_ftp_port(self, *args):
        return self.rdb.is_ftp_port(*args)

    def set_organization_of_port(self, *args):
        return self.rdb.set_organization_of_port(*args)

    def get_organization_of_port(self, *args):
        return self.rdb.get_organization_of_port(*args)

    def add_zeek_file(self, *args):
        return self.rdb.add_zeek_file(*args)

    def get_all_zeek_file(self, *args):
        return self.rdb.get_all_zeek_file(*args)

    def get_gateway_ip(self, *args):
        return self.rdb.get_gateway_ip(*args)

    def get_gateway_mac(self, *args):
        return self.rdb.get_gateway_mac(*args)

    def get_gateway_MAC_Vendor(self, *args):
        return self.rdb.get_gateway_MAC_Vendor(*args)

    def set_default_gateway(self, *args):
        return self.rdb.set_default_gateway(*args)

    def get_domain_resolution(self, *args):
        return self.rdb.get_domain_resolution(*args)

    def get_all_dns_resolutions(self, *args):
        return self.rdb.get_all_dns_resolutions(*args)

    def set_passive_dns(self, *args):
        return self.rdb.set_passive_dns(*args)

    def get_passive_dns(self, *args):
        return self.rdb.get_passive_dns(*args)

    def get_reconnections_for_tw(self, *args):
        return self.rdb.get_reconnections_for_tw(*args)

    def setReconnections(self, *args):
        return self.rdb.setReconnections(*args)

    def get_host_ip(self, *args):
        return self.rdb.get_host_ip(*args)

    def set_host_ip(self, *args):
        return self.rdb.set_host_ip(*args)

    def set_asn_cache(self, *args):
        return self.rdb.set_asn_cache(*args)

    def get_asn_cache(self, *args):
        return self.rdb.get_asn_cache(*args)

    def store_process_PID(self, *args):
        return self.rdb.store_process_PID(*args)

    def get_pids(self, *args):
        return self.rdb.get_pids(*args)

    def set_org_info(self, *args):
        return self.rdb.set_org_info(*args)

    def get_org_info(self, *args):
        return self.rdb.get_org_info(*args)

    def get_org_IPs(self, *args):
        return self.rdb.get_org_IPs(*args)

    def set_whitelist(self, *args):
        return self.rdb.set_whitelist(*args)

    def get_all_whitelist(self, *args):
        return self.rdb.get_all_whitelist(*args)

    def get_whitelist(self, *args):
        return self.rdb.get_whitelist(*args)

    def store_dhcp_server(self, *args):
        return self.rdb.store_dhcp_server(*args)

    def save(self, *args):
        return self.rdb.save(*args)

    def load(self, *args):
        return self.rdb.load(*args)

    def is_valid_rdb_file(self, *args):
        return self.rdb.is_valid_rdb_file(*args)

    def set_last_warden_poll_time(self, *args):
        return self.rdb.set_last_warden_poll_time(*args)

    def get_last_warden_poll_time(self, *args):
        return self.rdb.get_last_warden_poll_time(*args)

    def store_blame_report(self, *args):
        return self.rdb.store_blame_report(*args)

    def store_zeek_path(self, *args):
        return self.rdb.store_zeek_path(*args)

    def get_zeek_path(self, *args):
        return self.rdb.get_zeek_path(*args)

    def store_std_file(self, *args, **kwargs):
        return self.rdb.store_std_file(*args, **kwargs)

    def get_stdfile(self, *args):
        return self.rdb.get_stdfile(*args)


    def set_evidence_causing_alert(self, *args):
        return self.rdb.set_evidence_causing_alert(*args)

    def get_evidence_causing_alert(self, *args):
        return self.rdb.get_evidence_causing_alert(*args)

    def get_evidence_by_ID(self, *args):
        return self.rdb.get_evidence_by_ID(*args)

    def is_detection_disabled(self, *args):
        return self.rdb.is_detection_disabled(*args)

    def set_flow_causing_evidence(self, *args):
        return self.rdb.set_flow_causing_evidence(*args)

    def get_flows_causing_evidence(self, *args):
        return self.rdb.get_flows_causing_evidence(*args)

    def setEvidence(self, *args, **kwargs):
        return self.rdb.setEvidence(*args, **kwargs)

    def init_evidence_number(self, *args):
        return self.rdb.init_evidence_number(*args)

    def get_evidence_number(self, *args):
        return self.rdb.get_evidence_number(*args)

    def mark_evidence_as_processed(self, *args):
        return self.rdb.mark_evidence_as_processed(*args)

    def is_evidence_processed(self, *args):
        return self.rdb.is_evidence_processed(*args)

    def set_evidence_for_profileid(self, *args):
        return self.rdb.set_evidence_for_profileid(*args)

    def deleteEvidence(self, *args):
        return self.rdb.deleteEvidence(*args)

    def cache_whitelisted_evidence_ID(self, *args):
        return self.rdb.cache_whitelisted_evidence_ID(*args)

    def is_whitelisted_evidence(self, *args):
        return self.rdb.is_whitelisted_evidence(*args)

    def remove_whitelisted_evidence(self, *args):
        return self.rdb.remove_whitelisted_evidence(*args)

    def get_profileid_twid_alerts(self, *args):
        return self.rdb.get_profileid_twid_alerts(*args)

    def getEvidenceForTW(self, *args):
        return self.rdb.getEvidenceForTW(*args)

    def update_threat_level(self, *args):
        return self.rdb.update_threat_level(*args)

    def init_ti_queue(self, *args):
        return self.rdb.init_ti_queue(*args)

    def set_loaded_ti_files(self, *args):
        return self.rdb.set_loaded_ti_files(*args)

    def get_loaded_ti_files(self, *args):
        return self.rdb.get_loaded_ti_files(*args)

    def mark_as_analyzed_by_ti_module(self, *args):
        return self.rdb.mark_as_analyzed_by_ti_module(*args)

    def get_ti_queue_size(self, *args):
        return self.rdb.get_ti_queue_size(*args)

    def give_threat_intelligence(self, *args, **kwargs):
        return self.rdb.give_threat_intelligence(*args, **kwargs)

    def delete_ips_from_IoC_ips(self, *args):
        return self.rdb.delete_ips_from_IoC_ips(*args)

    def delete_domains_from_IoC_domains(self, *args):
        return self.rdb.delete_domains_from_IoC_domains(*args)

    def add_ips_to_IoC(self, *args):
        return self.rdb.add_ips_to_IoC(*args)

    def add_domains_to_IoC(self, *args):
        return self.rdb.add_domains_to_IoC(*args)

    def add_ip_range_to_IoC(self, *args):
        return self.rdb.add_ip_range_to_IoC(*args)

    def add_asn_to_IoC(self, *args):
        return self.rdb.add_asn_to_IoC(*args)

    def is_blacklisted_ASN(self, *args):
        return self.rdb.is_blacklisted_ASN(*args)

    def add_ja3_to_IoC(self, *args):
        return self.rdb.add_ja3_to_IoC(*args)

    def add_jarm_to_IoC(self, *args):
        return self.rdb.add_jarm_to_IoC(*args)

    def add_ssl_sha1_to_IoC(self, *args):
        return self.rdb.add_ssl_sha1_to_IoC(*args)

    def get_malicious_ip_ranges(self, *args):
        return self.rdb.get_malicious_ip_ranges(*args)

    def get_IPs_in_IoC(self, *args):
        return self.rdb.get_IPs_in_IoC(*args)

    def get_Domains_in_IoC(self, *args):
        return self.rdb.get_Domains_in_IoC(*args)

    def get_ja3_in_IoC(self, *args):
        return self.rdb.get_ja3_in_IoC(*args)

    def is_malicious_jarm(self, *args):
        return self.rdb.is_malicious_jarm(*args)

    def search_IP_in_IoC(self, *args):
        return self.rdb.search_IP_in_IoC(*args)

    def set_malicious_ip(self, *args):
        return self.rdb.set_malicious_ip(*args)

    def set_malicious_domain(self, *args):
        return self.rdb.set_malicious_domain(*args)

    def get_malicious_ip(self, *args):
        return self.rdb.get_malicious_ip(*args)

    def get_malicious_domain(self, *args):
        return self.rdb.get_malicious_domain(*args)

    def get_ssl_info(self, *args):
        return self.rdb.get_ssl_info(*args)

    def is_domain_malicious(self, *args):
        return self.rdb.is_domain_malicious(*args)

    def delete_feed(self, *args):
        return self.rdb.delete_feed(*args)

    def is_profile_malicious(self, *args):
        return self.rdb.is_profile_malicious(*args)

    def set_TI_file_info(self, *args):
        return self.rdb.set_TI_file_info(*args)

    def set_last_update_time(self, *args):
        return self.rdb.set_last_update_time(*args)

    def get_TI_file_info(self, *args):
        return self.rdb.get_TI_file_info(*args)

    def delete_file_info(self, *args):
        return self.rdb.delete_file_info(*args)

    def getURLData(self, *args):
        return self.rdb.getURLData(*args)

    def setNewURL(self, *args):
        return self.rdb.setNewURL(*args)

    def getDomainData(self, *args):
        return self.rdb.getDomainData(*args)

    def setNewDomain(self, *args):
        return self.rdb.setNewDomain(*args)

    def setInfoForDomains(self, *args, **kwargs):
        return self.rdb.setInfoForDomains(*args, **kwargs)

    def setInfoForURLs(self, *args):
        return self.rdb.setInfoForURLs(*args)
    def get_data_from_profile_tw(self, *args):
        return self.rdb.get_data_from_profile_tw(*args)

    def getOutTuplesfromProfileTW(self, *args):
        return self.rdb.getOutTuplesfromProfileTW(*args)

    def getInTuplesfromProfileTW(self, *args):
        return self.rdb.getInTuplesfromProfileTW(*args)

    def get_dhcp_flows(self, *args):
        return self.rdb.get_dhcp_flows(*args)

    def set_dhcp_flow(self, *args):
        return self.rdb.set_dhcp_flow(*args)

    def get_timewindow(self, *args):
        return self.rdb.get_timewindow(*args)

    def add_out_http(self, *args):
        return self.rdb.add_out_http(*args)

    def add_out_dns(self, *args):
        return self.rdb.add_out_dns(*args)

    def add_port(self, *args):
        return self.rdb.add_port(*args)

    def getFinalStateFromFlags(self, *args):
        return self.rdb.getFinalStateFromFlags(*args)

    def getDataFromProfileTW(self, *args):
        return self.rdb.getDataFromProfileTW(*args)

    def add_ips(self, *args):
        return self.rdb.add_ips(*args)

    def get_altflow_from_uid(self, *args):
        return self.rdb.get_altflow_from_uid(*args)

    def get_all_flows_in_profileid_twid(self, *args):
        return self.rdb.get_all_flows_in_profileid_twid(*args)

    def get_all_flows_in_profileid(self, *args):
        return self.rdb.get_all_flows_in_profileid(*args)

    def get_all_flows(self, *args):
        return self.rdb.get_all_flows(*args)

    def get_all_contacted_ips_in_profileid_twid(self, *args):
        return self.rdb.get_all_contacted_ips_in_profileid_twid(*args)

    def markProfileTWAsBlocked(self, *args):
        return self.rdb.markProfileTWAsBlocked(*args)

    def getBlockedProfTW(self, *args):
        return self.rdb.getBlockedProfTW(*args)

    def checkBlockedProfTW(self, *args):
        return self.rdb.checkBlockedProfTW(*args)

    def wasProfileTWModified(self, *args):
        return self.rdb.wasProfileTWModified(*args)

    def add_software_to_profile(self, *args):
        return self.rdb.add_software_to_profile(*args)

    def get_total_flows(self, *args):
        return self.rdb.get_total_flows(*args)

    def add_out_ssh(self, *args):
        return self.rdb.add_out_ssh(*args)

    def add_out_notice(self, *args):
        return self.rdb.add_out_notice(*args)

    def add_out_ssl(self, *args):
        return self.rdb.add_out_ssl(*args)

    def getProfileIdFromIP(self, *args):
        return self.rdb.getProfileIdFromIP(*args)

    def getProfiles(self, *args):
        return self.rdb.getProfiles(*args)

    def getTWsfromProfile(self, *args):
        return self.rdb.getTWsfromProfile(*args)

    def getamountTWsfromProfile(self, *args):
        return self.rdb.getamountTWsfromProfile(*args)

    def getSrcIPsfromProfileTW(self, *args):
        return self.rdb.getSrcIPsfromProfileTW(*args)

    def getDstIPsfromProfileTW(self, *args):
        return self.rdb.getDstIPsfromProfileTW(*args)

    def getT2ForProfileTW(self, *args):
        return self.rdb.getT2ForProfileTW(*args)

    def has_profile(self, *args):
        return self.rdb.has_profile(*args)

    def getProfilesLen(self, *args):
        return self.rdb.getProfilesLen(*args)

    def getLastTWforProfile(self, *args):
        return self.rdb.getLastTWforProfile(*args)

    def getFirstTWforProfile(self, *args):
        return self.rdb.getFirstTWforProfile(*args)

    def getTWofTime(self, *args):
        return self.rdb.getTWofTime(*args)

    def addNewOlderTW(self, *args):
        return self.rdb.addNewOlderTW(*args)

    def addNewTW(self, *args):
        return self.rdb.addNewTW(*args)

    def getTimeTW(self, *args):
        return self.rdb.getTimeTW(*args)

    def getAmountTW(self, *args):
        return self.rdb.getAmountTW(*args)

    def getModifiedTWSinceTime(self, *args):
        return self.rdb.getModifiedTWSinceTime(*args)

    def getModifiedProfilesSince(self, *args):
        return self.rdb.getModifiedProfilesSince(*args)

    def add_mac_addr_to_profile(self, *args):
        return self.rdb.add_mac_addr_to_profile(*args)

    def get_mac_addr_from_profile(self, *args):
        return self.rdb.get_mac_addr_from_profile(*args)

    def add_user_agent_to_profile(self, *args):
        return self.rdb.add_user_agent_to_profile(*args)

    def add_all_user_agent_to_profile(self, *args):
        return self.rdb.add_all_user_agent_to_profile(*args)

    def get_software_from_profile(self, *args):
        return self.rdb.get_software_from_profile(*args)

    def get_user_agent_from_profile(self, *args):
        return self.rdb.get_user_agent_from_profile(*args)

    def mark_profile_as_dhcp(self, *args):
        return self.rdb.mark_profile_as_dhcp(*args)

    def addProfile(self, *args):
        return self.rdb.addProfile(*args)

    def set_profile_module_label(self, *args):
        return self.rdb.set_profile_module_label(*args)

    def check_TW_to_close(self, *args):
        return self.rdb.check_TW_to_close(*args)

    def check_health(self):
        self.rdb.pubsub.check_health()

    def markProfileTWAsClosed(self, *args):
        return self.rdb.markProfileTWAsClosed(*args)

    def markProfileTWAsModified(self, *args):
        return self.rdb.markProfileTWAsModified(*args)

    def add_tuple(self, *args):
        return self.rdb.add_tuple(*args)

    def search_tws_for_flow(self, profileid, twid, uid, go_back=False):
        """
        Search for the given uid in the given twid, or the tws before
        :param go_back: how many hours back to search?
        """

        #TODO test this
        tws_to_search = self.rdb.get_tws_to_search(go_back)

        twid_number: int = int(twid.split('timewindow')[-1])
        while twid_number > -1 and tws_to_search > 0:
            flow = self.sqlite.get_flow(uid, twid=f'timewindow{twid_number}')

            uid = next(iter(flow))
            if flow[uid]:
                return flow

            twid_number -= 1
            # this reaches 0 when go_back is set to a number
            tws_to_search -= 1

        # uid isn't in this twid or any of the previous ones
        return {uid: None}

    def get_profile_modules_labels(self, *args):
        return self.rdb.get_profile_modules_labels(*args)

    def add_timeline_line(self, *args):
        return self.rdb.add_timeline_line(*args)

    def get_timeline_last_lines(self, *args):
        return self.rdb.get_timeline_last_lines(*args)

    def should_add(self, *args):
        return self.rdb.should_add(*args)

    def mark_profile_as_gateway(self, *args):
        return self.rdb.mark_profile_as_gateway(*args)

    def set_ipv6_of_profile(self, *args):
        return self.rdb.set_ipv6_of_profile(*args)

    def set_ipv4_of_profile(self, *args):
        return self.rdb.set_ipv4_of_profile(*args)

    def get_mac_vendor_from_profile(self, *args):
        return self.rdb.get_mac_vendor_from_profile(*args)

    def get_hostname_from_profile(self, *args):
        return self.rdb.get_hostname_from_profile(*args)

    def get_ipv4_from_profile(self, *args):
        return self.rdb.get_ipv4_from_profile(*args)

    def get_ipv6_from_profile(self, *args):
        return self.rdb.get_ipv6_from_profile(*args)

    def get_the_other_ip_version(self, *args):
        return self.rdb.get_the_other_ip_version(*args)

    def get_separator(self):
        return self.rdb.separator

    def get_normal_label(self):
        return self.rdb.normal_label

    def get_malicious_label(self):
        return self.rdb.malicious_label

    def init_tables(self, *args):
        return self.sqlite.init_tables(*args)

    def _init_db(self, *args):
        return self.sqlite._init_db(*args)

    def create_table(self, *args):
        return self.sqlite.create_table(*args)

    def set_flow_label(self, *args):
        return self.sqlite.set_flow_label(*args)

    def get_flow(self, *args, **kwargs):
        return self.sqlite.get_flow(*args, **kwargs)

    def add_flow(self, flow, raw_flow: str, profileid: str, twid:str, label='benign'):
        # stores it in the db
        self.sqlite.add_flow(flow.uid, raw_flow, profileid, twid, label=label)
        # handles the channels and labels etc.
        return self.rdb.add_flow(
            flow,
            profileid=profileid,
            twid=twid,
            label=label
        )


    def add_altflow(self, *args):
        return self.sqlite.add_altflow(*args)

    def insert(self, *args):
        return self.sqlite.insert(*args)

    def update(self, *args):
        return self.sqlite.update(*args)

    def delete(self, *args):
        return self.sqlite.delete(*args)

    def select(self, *args):
        return self.sqlite.select(*args)

    def execute_query(self, *args):
        return self.sqlite.execute_query(*args)

    def close(self, *args):
        return self.sqlite.close(*args)
