from slips_files.core.database.redis_db.database import RedisDB
from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.common.config_parser import ConfigParser

class DBManager:
    """
    This class will be calling methods from the appropriate db.
    each method added to any of the dbs should have a
    handler in here
    """
    def __init__(
            self,
            output_dir,
            output_queue,
            redis_port,
            start_sqlite=True,
            **kwargs
    ):
        self.output_dir = output_dir
        self.output_queue = output_queue
        self.redis_port = redis_port

        self.rdb = RedisDB(redis_port, output_queue, **kwargs)

        # in some rare cases we don't wanna start sqlite,
        # like when using -S
        # we just want to connect to redis to get the PIDs
        self.sqlite = None
        if start_sqlite:
            self.sqlite = self.create_sqlite_db(output_dir, output_queue)


    def create_sqlite_db(self, output_dir, output_queue):
        return SQLiteDB(output_dir, output_queue)

    @classmethod
    def read_configuration(cls):
        conf = ConfigParser()
        cls.width = conf.get_tw_width_as_float()

    def get_sqlite_db_path(self) -> str:
        return self.sqlite.get_db_path()

    def iterate_flows(self, *args, **kwargs):
        return self.sqlite.iterate_flows(*args, **kwargs)


    def get_columns(self, *args, **kwargs):
        return self.sqlite.get_columns(*args, **kwargs)

    def publish(self, *args, **kwargs):
        return self.rdb.publish(*args, **kwargs)

    def subscribe(self, *args, **kwargs):
        return self.rdb.subscribe(*args, **kwargs)

    def publish_stop(self, *args, **kwargs):
        return self.rdb.publish_stop(*args, **kwargs)

    def get_message(self, *args, **kwargs):
        return self.rdb.get_message(*args, **kwargs)

    def print(self, *args, **kwargs):
        return self.rdb.print(*args, **kwargs)

    def getIPData(self, *args, **kwargs):
        return self.rdb.getIPData(*args, **kwargs)

    def set_new_ip(self, *args, **kwargs):
        return self.rdb.set_new_ip(*args, **kwargs)

    def ask_for_ip_info(self, *args, **kwargs):
        return self.rdb.ask_for_ip_info(*args, **kwargs)

    @classmethod
    def discard_obj(cls):
        """
        when connecting on multiple ports, this dbmanager since it's a singelton
        returns the same instance of the already used db
        to fix this, we call this function every time we find a used db
        that slips should connect to
        """
        cls._obj = None

    def update_times_contacted(self, *args, **kwargs):
        return self.rdb.update_times_contacted(*args, **kwargs)

    def update_ip_info(self, *args, **kwargs):
        return self.rdb.update_ip_info(*args, **kwargs)

    def getSlipsInternalTime(self, *args, **kwargs):
        return self.rdb.getSlipsInternalTime(*args, **kwargs)

    def get_equivalent_tws(self, *args, **kwargs):
        return self.rdb.get_equivalent_tws(*args, **kwargs)

    def set_local_network(self, *args, **kwargs):
        return self.rdb.set_local_network(*args, **kwargs)

    def get_local_network(self, *args, **kwargs):
        return self.rdb.get_local_network(*args, **kwargs)

    def get_label_count(self, *args, **kwargs):
        return self.rdb.get_label_count(*args, **kwargs)

    def get_disabled_modules(self, *args, **kwargs):
        return self.rdb.get_disabled_modules(*args, **kwargs)

    def set_input_metadata(self, *args, **kwargs):
        return self.rdb.set_input_metadata(*args, **kwargs)

    def get_zeek_output_dir(self, *args, **kwargs):
        return self.rdb.get_zeek_output_dir(*args, **kwargs)

    def get_input_type(self, *args, **kwargs):
        return self.rdb.get_input_type(*args, **kwargs)

    def get_output_dir(self, *args, **kwargs):
        return self.rdb.get_output_dir(*args, **kwargs)

    def get_input_file(self, *args, **kwargs):
        return self.rdb.get_input_file(*args, **kwargs)

    def setInfoForIPs(self, *args, **kwargs):
        return self.rdb.setInfoForIPs(*args, **kwargs)

    def get_p2p_reports_about_ip(self, *args, **kwargs):
        return self.rdb.get_p2p_reports_about_ip(*args, **kwargs)

    def store_p2p_report(self, *args, **kwargs):
        return self.rdb.store_p2p_report(*args, **kwargs)

    def get_dns_resolution(self, *args, **kwargs):
        return self.rdb.get_dns_resolution(*args, **kwargs)

    def is_ip_resolved(self, *args, **kwargs):
        return self.rdb.is_ip_resolved(*args, **kwargs)

    def delete_dns_resolution(self, *args, **kwargs):
        return self.rdb.delete_dns_resolution(*args, **kwargs)

    def should_store_resolution(self, *args, **kwargs):
        return self.rdb.should_store_resolution(*args, **kwargs)

    def set_dns_resolution(self, *args, **kwargs):
        return self.rdb.set_dns_resolution(*args, **kwargs)

    def set_domain_resolution(self, *args, **kwargs):
        return self.rdb.set_domain_resolution(*args, **kwargs)

    def get_redis_server_PID(self, *args, **kwargs):
        return self.rdb.get_redis_server_PID(*args, **kwargs)

    def set_slips_mode(self, *args, **kwargs):
        return self.rdb.set_slips_mode(*args, **kwargs)

    def get_slips_mode(self, *args, **kwargs):
        return self.rdb.get_slips_mode(*args, **kwargs)

    def get_modified_ips_in_the_last_tw(self, *args, **kwargs):
        return self.rdb.get_modified_ips_in_the_last_tw(*args, **kwargs)

    def is_connection_error_logged(self, *args, **kwargs):
        return self.rdb.is_connection_error_logged(*args, **kwargs)

    def mark_connection_error_as_logged(self, *args, **kwargs):
        return self.rdb.mark_connection_error_as_logged(*args, **kwargs)

    def get_redis_keys_len(self):
        """
        returns all the keys in redis
        """
        return int(self.rdb.get_redis_keys_len())

    def was_ip_seen_in_connlog_before(self, *args, **kwargs):
        return self.rdb.was_ip_seen_in_connlog_before(*args, **kwargs)

    def mark_srcip_as_seen_in_connlog(self, *args, **kwargs):
        return self.rdb.mark_srcip_as_seen_in_connlog(*args, **kwargs)

    def is_gw_mac(self, *args, **kwargs):
        return self.rdb.is_gw_mac(*args, **kwargs)

    def get_ip_of_mac(self, *args, **kwargs):
        return self.rdb.get_ip_of_mac(*args, **kwargs)

    def get_modified_tw(self, *args, **kwargs):
        return self.rdb.get_modified_tw(*args, **kwargs)

    def get_field_separator(self, *args, **kwargs):
        return self.rdb.get_field_separator(*args, **kwargs)

    def store_tranco_whitelisted_domain(self, *args, **kwargs):
        return self.rdb.store_tranco_whitelisted_domain(*args, **kwargs)

    def is_whitelisted_tranco_domain(self, *args, **kwargs):
        return self.rdb.is_whitelisted_tranco_domain(*args, **kwargs)

    def set_growing_zeek_dir(self, *args, **kwargs):
        return self.rdb.set_growing_zeek_dir(*args, **kwargs)

    def is_growing_zeek_dir(self, *args, **kwargs):
        return self.rdb.is_growing_zeek_dir(*args, **kwargs)

    def get_ip_identification(self, *args, **kwargs):
        return self.rdb.get_ip_identification(*args,  **kwargs)

    def get_multiaddr(self, *args, **kwargs):
        return self.rdb.get_multiaddr(*args, **kwargs)

    def get_labels(self, *args, **kwargs):
        return self.rdb.get_labels(*args, **kwargs)

    def set_port_info(self, *args, **kwargs):
        return self.rdb.set_port_info(*args, **kwargs)

    def get_port_info(self, *args, **kwargs):
        return self.rdb.get_port_info(*args, **kwargs)

    def set_ftp_port(self, *args, **kwargs):
        return self.rdb.set_ftp_port(*args, **kwargs)

    def is_ftp_port(self, *args, **kwargs):
        return self.rdb.is_ftp_port(*args, **kwargs)

    def set_organization_of_port(self, *args, **kwargs):
        return self.rdb.set_organization_of_port(*args, **kwargs)

    def get_organization_of_port(self, *args, **kwargs):
        return self.rdb.get_organization_of_port(*args, **kwargs)

    def add_zeek_file(self, *args, **kwargs):
        return self.rdb.add_zeek_file(*args, **kwargs)

    def get_all_zeek_file(self, *args, **kwargs):
        return self.rdb.get_all_zeek_file(*args, **kwargs)

    def get_gateway_ip(self, *args, **kwargs):
        return self.rdb.get_gateway_ip(*args, **kwargs)

    def get_gateway_mac(self, *args, **kwargs):
        return self.rdb.get_gateway_mac(*args, **kwargs)

    def get_gateway_MAC_Vendor(self, *args, **kwargs):
        return self.rdb.get_gateway_MAC_Vendor(*args, **kwargs)

    def set_default_gateway(self, *args, **kwargs):
        return self.rdb.set_default_gateway(*args, **kwargs)

    def get_domain_resolution(self, *args, **kwargs):
        return self.rdb.get_domain_resolution(*args, **kwargs)

    def get_all_dns_resolutions(self, *args, **kwargs):
        return self.rdb.get_all_dns_resolutions(*args, **kwargs)

    def set_passive_dns(self, *args, **kwargs):
        return self.rdb.set_passive_dns(*args, **kwargs)

    def get_passive_dns(self, *args, **kwargs):
        return self.rdb.get_passive_dns(*args, **kwargs)

    def get_reconnections_for_tw(self, *args, **kwargs):
        return self.rdb.get_reconnections_for_tw(*args, **kwargs)

    def setReconnections(self, *args, **kwargs):
        return self.rdb.setReconnections(*args, **kwargs)

    def get_host_ip(self, *args, **kwargs):
        return self.rdb.get_host_ip(*args, **kwargs)

    def set_host_ip(self, *args, **kwargs):
        return self.rdb.set_host_ip(*args, **kwargs)

    def set_asn_cache(self, *args, **kwargs):
        return self.rdb.set_asn_cache(*args, **kwargs)

    def get_asn_cache(self, *args, **kwargs):
        return self.rdb.get_asn_cache(*args, **kwargs)

    def store_process_PID(self, *args, **kwargs):
        return self.rdb.store_process_PID(*args, **kwargs)

    def get_pids(self, *args, **kwargs):
        return self.rdb.get_pids(*args, **kwargs)

    def set_org_info(self, *args, **kwargs):
        return self.rdb.set_org_info(*args, **kwargs)

    def get_org_info(self, *args, **kwargs):
        return self.rdb.get_org_info(*args, **kwargs)

    def get_org_IPs(self, *args, **kwargs):
        return self.rdb.get_org_IPs(*args, **kwargs)

    def set_whitelist(self, *args, **kwargs):
        return self.rdb.set_whitelist(*args, **kwargs)

    def get_all_whitelist(self, *args, **kwargs):
        return self.rdb.get_all_whitelist(*args, **kwargs)

    def get_whitelist(self, *args, **kwargs):
        return self.rdb.get_whitelist(*args, **kwargs)

    def store_dhcp_server(self, *args, **kwargs):
        return self.rdb.store_dhcp_server(*args, **kwargs)

    def save(self, *args, **kwargs):
        return self.rdb.save(*args, **kwargs)

    def load(self, *args, **kwargs):
        return self.rdb.load(*args, **kwargs)

    def is_valid_rdb_file(self, *args, **kwargs):
        return self.rdb.is_valid_rdb_file(*args, **kwargs)

    def set_last_warden_poll_time(self, *args, **kwargs):
        return self.rdb.set_last_warden_poll_time(*args, **kwargs)

    def get_last_warden_poll_time(self, *args, **kwargs):
        return self.rdb.get_last_warden_poll_time(*args, **kwargs)

    def store_blame_report(self, *args, **kwargs):
        return self.rdb.store_blame_report(*args, **kwargs)

    def store_zeek_path(self, *args, **kwargs):
        return self.rdb.store_zeek_path(*args, **kwargs)

    def get_zeek_path(self, *args, **kwargs):
        return self.rdb.get_zeek_path(*args, **kwargs)

    def store_std_file(self, *args, **kwargs):
        return self.rdb.store_std_file(*args, **kwargs)

    def get_stdfile(self, *args, **kwargs):
        return self.rdb.get_stdfile(*args, **kwargs)


    def set_evidence_causing_alert(self, *args, **kwargs):
        return self.rdb.set_evidence_causing_alert(*args, **kwargs)

    def get_evidence_causing_alert(self, *args, **kwargs):
        return self.rdb.get_evidence_causing_alert(*args, **kwargs)

    def get_evidence_by_ID(self, *args, **kwargs):
        return self.rdb.get_evidence_by_ID(*args, **kwargs)

    def is_detection_disabled(self, *args, **kwargs):
        return self.rdb.is_detection_disabled(*args, **kwargs)

    def set_flow_causing_evidence(self, *args, **kwargs):
        return self.rdb.set_flow_causing_evidence(*args, **kwargs)

    def get_flows_causing_evidence(self, *args, **kwargs):
        """returns the list of uids of the flows causing evidence"""
        return self.rdb.get_flows_causing_evidence(*args, **kwargs)

    def setEvidence(self, *args, **kwargs):
        return self.rdb.setEvidence(*args, **kwargs)

    def get_user_agents_count(self, *args, **kwargs):
        return self.rdb.get_user_agents_count(*args, **kwargs)

    def init_evidence_number(self, *args, **kwargs):
        return self.rdb.init_evidence_number(*args, **kwargs)

    def get_evidence_number(self, *args, **kwargs):
        return self.rdb.get_evidence_number(*args, **kwargs)

    def mark_evidence_as_processed(self, *args, **kwargs):
        return self.rdb.mark_evidence_as_processed(*args, **kwargs)

    def is_evidence_processed(self, *args, **kwargs):
        return self.rdb.is_evidence_processed(*args, **kwargs)

    def set_evidence_for_profileid(self, *args, **kwargs):
        return self.rdb.set_evidence_for_profileid(*args, **kwargs)

    def deleteEvidence(self, *args, **kwargs):
        return self.rdb.deleteEvidence(*args, **kwargs)

    def cache_whitelisted_evidence_ID(self, *args, **kwargs):
        return self.rdb.cache_whitelisted_evidence_ID(*args, **kwargs)

    def is_whitelisted_evidence(self, *args, **kwargs):
        return self.rdb.is_whitelisted_evidence(*args, **kwargs)

    def remove_whitelisted_evidence(self, *args, **kwargs):
        return self.rdb.remove_whitelisted_evidence(*args, **kwargs)

    def get_profileid_twid_alerts(self, *args, **kwargs):
        return self.rdb.get_profileid_twid_alerts(*args, **kwargs)

    def getEvidenceForTW(self, *args, **kwargs):
        return self.rdb.getEvidenceForTW(*args, **kwargs)

    def update_threat_level(self, *args, **kwargs):
        return self.rdb.update_threat_level(*args, **kwargs)

    def set_loaded_ti_files(self, *args, **kwargs):
        return self.rdb.set_loaded_ti_files(*args, **kwargs)

    def get_loaded_ti_files(self, *args, **kwargs):
        return self.rdb.get_loaded_ti_files(*args, **kwargs)

    def mark_as_analyzed_by_ti_module(self, *args, **kwargs):
        return self.rdb.mark_as_analyzed_by_ti_module(*args, **kwargs)

    def get_ti_queue_size(self, *args, **kwargs):
        return self.rdb.get_ti_queue_size(*args, **kwargs)

    def set_cyst_enabled(self, *args, **kwargs):
        return self.rdb.set_cyst_enabled(*args, **kwargs)

    def is_cyst_enabled(self, *args, **kwargs):
        return self.rdb.is_cyst_enabled(*args, **kwargs)

    def give_threat_intelligence(self, *args, **kwargs):
        return self.rdb.give_threat_intelligence(*args, **kwargs)

    def delete_ips_from_IoC_ips(self, *args, **kwargs):
        return self.rdb.delete_ips_from_IoC_ips(*args, **kwargs)

    def delete_domains_from_IoC_domains(self, *args, **kwargs):
        return self.rdb.delete_domains_from_IoC_domains(*args, **kwargs)

    def add_ips_to_IoC(self, *args, **kwargs):
        return self.rdb.add_ips_to_IoC(*args, **kwargs)

    def add_domains_to_IoC(self, *args, **kwargs):
        return self.rdb.add_domains_to_IoC(*args, **kwargs)

    def add_ip_range_to_IoC(self, *args, **kwargs):
        return self.rdb.add_ip_range_to_IoC(*args, **kwargs)

    def add_asn_to_IoC(self, *args, **kwargs):
        return self.rdb.add_asn_to_IoC(*args, **kwargs)

    def is_blacklisted_ASN(self, *args, **kwargs):
        return self.rdb.is_blacklisted_ASN(*args, **kwargs)

    def add_ja3_to_IoC(self, *args, **kwargs):
        return self.rdb.add_ja3_to_IoC(*args, **kwargs)

    def add_jarm_to_IoC(self, *args, **kwargs):
        return self.rdb.add_jarm_to_IoC(*args, **kwargs)

    def add_ssl_sha1_to_IoC(self, *args, **kwargs):
        return self.rdb.add_ssl_sha1_to_IoC(*args, **kwargs)

    def get_malicious_ip_ranges(self, *args, **kwargs):
        return self.rdb.get_malicious_ip_ranges(*args, **kwargs)

    def get_IPs_in_IoC(self, *args, **kwargs):
        return self.rdb.get_IPs_in_IoC(*args, **kwargs)

    def get_Domains_in_IoC(self, *args, **kwargs):
        return self.rdb.get_Domains_in_IoC(*args, **kwargs)

    def get_ja3_in_IoC(self, *args, **kwargs):
        return self.rdb.get_ja3_in_IoC(*args, **kwargs)

    def is_malicious_jarm(self, *args, **kwargs):
        return self.rdb.is_malicious_jarm(*args, **kwargs)

    def search_IP_in_IoC(self, *args, **kwargs):
        return self.rdb.search_IP_in_IoC(*args, **kwargs)

    def set_malicious_ip(self, *args, **kwargs):
        return self.rdb.set_malicious_ip(*args, **kwargs)

    def set_malicious_domain(self, *args, **kwargs):
        return self.rdb.set_malicious_domain(*args, **kwargs)

    def get_malicious_ip(self, *args, **kwargs):
        return self.rdb.get_malicious_ip(*args, **kwargs)

    def get_malicious_domain(self, *args, **kwargs):
        return self.rdb.get_malicious_domain(*args, **kwargs)

    def get_ssl_info(self, *args, **kwargs):
        return self.rdb.get_ssl_info(*args, **kwargs)

    def is_domain_malicious(self, *args, **kwargs):
        return self.rdb.is_domain_malicious(*args, **kwargs)

    def delete_feed(self, *args, **kwargs):
        return self.rdb.delete_feed(*args, **kwargs)

    def is_profile_malicious(self, *args, **kwargs):
        return self.rdb.is_profile_malicious(*args, **kwargs)

    def set_TI_file_info(self, *args, **kwargs):
        return self.rdb.set_TI_file_info(*args, **kwargs)

    def set_last_update_time(self, *args, **kwargs):
        return self.rdb.set_last_update_time(*args, **kwargs)

    def get_TI_file_info(self, *args, **kwargs):
        return self.rdb.get_TI_file_info(*args, **kwargs)

    def delete_file_info(self, *args, **kwargs):
        return self.rdb.delete_file_info(*args, **kwargs)

    def getURLData(self, *args, **kwargs):
        return self.rdb.getURLData(*args, **kwargs)

    def setNewURL(self, *args, **kwargs):
        return self.rdb.setNewURL(*args, **kwargs)

    def getDomainData(self, *args, **kwargs):
        return self.rdb.getDomainData(*args, **kwargs)

    def setNewDomain(self, *args, **kwargs):
        return self.rdb.setNewDomain(*args, **kwargs)

    def setInfoForDomains(self, *args, **kwargs):
        return self.rdb.setInfoForDomains(*args, **kwargs)

    def setInfoForURLs(self, *args, **kwargs):
        return self.rdb.setInfoForURLs(*args, **kwargs)
    def get_data_from_profile_tw(self, *args, **kwargs):
        return self.rdb.get_data_from_profile_tw(*args, **kwargs)

    def getOutTuplesfromProfileTW(self, *args, **kwargs):
        return self.rdb.getOutTuplesfromProfileTW(*args, **kwargs)

    def getInTuplesfromProfileTW(self, *args, **kwargs):
        return self.rdb.getInTuplesfromProfileTW(*args, **kwargs)

    def get_dhcp_flows(self, *args, **kwargs):
        return self.rdb.get_dhcp_flows(*args, **kwargs)

    def set_dhcp_flow(self, *args, **kwargs):
        return self.rdb.set_dhcp_flow(*args, **kwargs)

    def get_timewindow(self, *args, **kwargs):
        return self.rdb.get_timewindow(*args, **kwargs)

    def add_out_http(self, *args, **kwargs):
        return self.rdb.add_out_http(*args, **kwargs)

    def add_out_dns(self, *args, **kwargs):
        return self.rdb.add_out_dns(*args, **kwargs)

    def add_port(self, *args, **kwargs):
        return self.rdb.add_port(*args, **kwargs)

    def getFinalStateFromFlags(self, *args, **kwargs):
        return self.rdb.getFinalStateFromFlags(*args, **kwargs)

    def getDataFromProfileTW(self, *args, **kwargs):
        return self.rdb.getDataFromProfileTW(*args, **kwargs)

    def add_ips(self, *args, **kwargs):
        return self.rdb.add_ips(*args, **kwargs)

    def get_altflow_from_uid(self, *args, **kwargs):
        return self.sqlite.get_altflow_from_uid(*args, **kwargs)

    def get_all_flows_in_profileid_twid(self, *args, **kwargs):
        return self.sqlite.get_all_flows_in_profileid_twid(*args, **kwargs)

    def get_all_flows_in_profileid(self, *args, **kwargs):
        return self.sqlite.get_all_flows_in_profileid(*args, **kwargs)

    def get_all_flows(self, *args, **kwargs):
        return self.sqlite.get_all_flows(*args, **kwargs)

    def get_all_contacted_ips_in_profileid_twid(self, *args, **kwargs):
        """
        Get all the contacted IPs in a given profile and TW
        """
        return self.sqlite.get_all_contacted_ips_in_profileid_twid(*args, **kwargs)

    def markProfileTWAsBlocked(self, *args, **kwargs):
        return self.rdb.markProfileTWAsBlocked(*args, **kwargs)

    def getBlockedProfTW(self, *args, **kwargs):
        return self.rdb.getBlockedProfTW(*args, **kwargs)

    def get_used_redis_port(self):
        return self.rdb.get_used_port()

    def checkBlockedProfTW(self, *args, **kwargs):
        return self.rdb.checkBlockedProfTW(*args, **kwargs)

    def wasProfileTWModified(self, *args, **kwargs):
        return self.rdb.wasProfileTWModified(*args, **kwargs)

    def add_software_to_profile(self, *args, **kwargs):
        return self.rdb.add_software_to_profile(*args, **kwargs)

    def get_total_flows(self, *args, **kwargs):
        return self.rdb.get_total_flows(*args, **kwargs)

    def add_out_ssh(self, *args, **kwargs):
        return self.rdb.add_out_ssh(*args, **kwargs)

    def add_out_notice(self, *args, **kwargs):
        return self.rdb.add_out_notice(*args, **kwargs)

    def add_out_ssl(self, *args, **kwargs):
        return self.rdb.add_out_ssl(*args, **kwargs)

    def getProfileIdFromIP(self, *args, **kwargs):
        return self.rdb.getProfileIdFromIP(*args, **kwargs)

    def getProfiles(self, *args, **kwargs):
        return self.rdb.getProfiles(*args, **kwargs)

    def getTWsfromProfile(self, *args, **kwargs):
        return self.rdb.getTWsfromProfile(*args, **kwargs)

    def get_number_of_tws_in_profile(self, *args, **kwargs):
        return self.rdb.get_number_of_tws_in_profile(*args, **kwargs)

    def getSrcIPsfromProfileTW(self, *args, **kwargs):
        return self.rdb.getSrcIPsfromProfileTW(*args, **kwargs)

    def getDstIPsfromProfileTW(self, *args, **kwargs):
        return self.rdb.getDstIPsfromProfileTW(*args, **kwargs)

    def getT2ForProfileTW(self, *args, **kwargs):
        return self.rdb.getT2ForProfileTW(*args, **kwargs)

    def has_profile(self, *args, **kwargs):
        return self.rdb.has_profile(*args, **kwargs)

    def get_profiles_len(self, *args, **kwargs):
        return self.rdb.get_profiles_len(*args, **kwargs)

    def get_last_twid_of_profile(self, *args, **kwargs):
        return self.rdb.get_last_twid_of_profile(*args, **kwargs)

    def getFirstTWforProfile(self, *args, **kwargs):
        return self.rdb.getFirstTWforProfile(*args, **kwargs)

    def getTWofTime(self, *args, **kwargs):
        return self.rdb.getTWofTime(*args, **kwargs)

    def addNewOlderTW(self, *args, **kwargs):
        return self.rdb.addNewOlderTW(*args, **kwargs)

    def addNewTW(self, *args, **kwargs):
        return self.rdb.addNewTW(*args, **kwargs)

    def getTimeTW(self, *args, **kwargs):
        return self.rdb.getTimeTW(*args, **kwargs)

    def getAmountTW(self, *args, **kwargs):
        return self.rdb.getAmountTW(*args, **kwargs)

    def getModifiedTWSinceTime(self, *args, **kwargs):
        return self.rdb.getModifiedTWSinceTime(*args, **kwargs)

    def getModifiedProfilesSince(self, *args, **kwargs):
        return self.rdb.getModifiedProfilesSince(*args, **kwargs)

    def add_mac_addr_to_profile(self, *args, **kwargs):
        return self.rdb.add_mac_addr_to_profile(*args, **kwargs)

    def get_mac_addr_from_profile(self, *args, **kwargs):
        return self.rdb.get_mac_addr_from_profile(*args, **kwargs)

    def add_user_agent_to_profile(self, *args, **kwargs):
        return self.rdb.add_user_agent_to_profile(*args, **kwargs)

    def get_first_user_agent(self, *args, **kwargs):
        return self.rdb.get_first_user_agent(*args, **kwargs)

    def add_all_user_agent_to_profile(self, *args, **kwargs):
        return self.rdb.add_all_user_agent_to_profile(*args, **kwargs)

    def get_software_from_profile(self, *args, **kwargs):
        return self.rdb.get_software_from_profile(*args, **kwargs)

    def get_user_agent_from_profile(self, *args, **kwargs):
        return self.rdb.get_user_agent_from_profile(*args, **kwargs)

    def mark_profile_as_dhcp(self, *args, **kwargs):
        return self.rdb.mark_profile_as_dhcp(*args, **kwargs)

    def addProfile(self, *args, **kwargs):
        return self.rdb.addProfile(*args, **kwargs)

    def set_profile_module_label(self, *args, **kwargs):
        return self.rdb.set_profile_module_label(*args, **kwargs)

    def check_TW_to_close(self, *args, **kwargs):
        return self.rdb.check_TW_to_close(*args, **kwargs)

    def check_health(self):
        self.rdb.pubsub.check_health()

    def markProfileTWAsClosed(self, *args, **kwargs):
        return self.rdb.markProfileTWAsClosed(*args, **kwargs)

    def markProfileTWAsModified(self, *args, **kwargs):
        return self.rdb.markProfileTWAsModified(*args, **kwargs)

    def add_tuple(self, *args, **kwargs):
        return self.rdb.add_tuple(*args, **kwargs)

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

    def get_profile_modules_labels(self, *args, **kwargs):
        return self.rdb.get_profile_modules_labels(*args, **kwargs)

    def add_timeline_line(self, *args, **kwargs):
        return self.rdb.add_timeline_line(*args, **kwargs)

    def get_timeline_last_lines(self, *args, **kwargs):
        return self.rdb.get_timeline_last_lines(*args, **kwargs)

    def should_add(self, *args, **kwargs):
        return self.rdb.should_add(*args, **kwargs)

    def mark_profile_as_gateway(self, *args, **kwargs):
        return self.rdb.mark_profile_as_gateway(*args, **kwargs)

    def set_ipv6_of_profile(self, *args, **kwargs):
        return self.rdb.set_ipv6_of_profile(*args, **kwargs)

    def set_ipv4_of_profile(self, *args, **kwargs):
        return self.rdb.set_ipv4_of_profile(*args, **kwargs)

    def get_mac_vendor_from_profile(self, *args, **kwargs):
        return self.rdb.get_mac_vendor_from_profile(*args, **kwargs)

    def get_hostname_from_profile(self, *args, **kwargs):
        return self.rdb.get_hostname_from_profile(*args, **kwargs)

    def add_host_name_to_profile(self, *args, **kwargs):
        return self.rdb.add_host_name_to_profile(*args, **kwargs)

    def get_ipv4_from_profile(self, *args, **kwargs):
        return self.rdb.get_ipv4_from_profile(*args, **kwargs)

    def get_ipv6_from_profile(self, *args, **kwargs):
        return self.rdb.get_ipv6_from_profile(*args, **kwargs)

    def get_the_other_ip_version(self, *args, **kwargs):
        return self.rdb.get_the_other_ip_version(*args, **kwargs)

    def get_separator(self):
        return self.rdb.separator

    def get_normal_label(self):
        return self.rdb.normal_label

    def get_malicious_label(self):
        return self.rdb.malicious_label

    def init_tables(self, *args, **kwargs):
        return self.sqlite.init_tables(*args, **kwargs)

    def _init_db(self, *args, **kwargs):
        return self.sqlite._init_db(*args, **kwargs)

    def create_table(self, *args, **kwargs):
        return self.sqlite.create_table(*args, **kwargs)

    def set_flow_label(self, *args, **kwargs):
        return self.sqlite.set_flow_label(*args, **kwargs)

    def get_flow(self, *args, **kwargs):
        """returns the raw flow as read from the log file"""
        return self.sqlite.get_flow(*args, **kwargs)

    def add_flow(self, flow, profileid: str, twid:str, label='benign'):
        # stores it in the db
        self.sqlite.add_flow(flow, profileid, twid, label=label)
        # handles the channels and labels etc.
        return self.rdb.add_flow(
            flow,
            profileid=profileid,
            twid=twid,
            label=label
        )

    def get_slips_start_time(self):
        return self.rdb.get_slips_start_time()

    def set_slips_internal_time(self, ts):
        return self.rdb.set_slips_internal_time(ts)

    def add_altflow(self, *args, **kwargs):
        return self.sqlite.add_altflow(*args, **kwargs)

    def insert(self, *args, **kwargs):
        return self.sqlite.insert(*args, **kwargs)

    def update(self, *args, **kwargs):
        return self.sqlite.update(*args, **kwargs)

    def delete(self, *args, **kwargs):
        return self.sqlite.delete(*args, **kwargs)

    def select(self, *args, **kwargs):
        return self.sqlite.select(*args, **kwargs)

    def execute_query(self, *args, **kwargs):
        return self.sqlite.execute_query(*args, **kwargs)

    def get_pid_of(self, *args, **kwargs):
        return self.rdb.get_pid_of(*args, **kwargs)

    def get_name_of_module_at(self, *args, **kwargs):
        return self.rdb.get_name_of_module_at(*args, **kwargs)

    def get_evidence_detection_threshold(self, *args, **kwargs):
        return self.rdb.get_evidence_detection_threshold(*args, **kwargs)

    def get_flows_count(self, *args, **kwargs):
        return self.sqlite.get_flows_count(*args, **kwargs)

    def get_redis_pid(self, *args, **kwargs):
        return self.rdb.get_redis_pid(*args, **kwargs)

    def export_labeled_flows(self, *args, **kwargs):
        """
        exports the labeled flows and altflows stored in sqlite
        db to json or csv based on the config file
        """
        self.sqlite.export_labeled_flows(self.get_output_dir(), *args, **kwargs)


    def get_commit(self, *args, **kwargs):
        return self.rdb.get_commit(*args, **kwargs)

    def get_branch(self, *args, **kwargs):
        return self.rdb.get_branch(*args, **kwargs)

    def add_alert(self, alert: dict):
        twid_starttime: float = self.rdb.getTimeTW(alert['profileid'], alert['twid'])
        twid_endtime: float = twid_starttime + RedisDB.width
        alert.update({'tw_start': twid_starttime, 'tw_end': twid_endtime})
        return self.sqlite.add_alert(alert)

    def close(self, *args, **kwargs):
        self.rdb.r.close()
        self.rdb.rcache.close()
        # when stopping the daemon using -S, slips doesn't start the sqlite db
        if self.sqlite:
            self.sqlite.close(*args, **kwargs)
