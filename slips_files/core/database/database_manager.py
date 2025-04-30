# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import (
    List,
    Dict,
)

from slips_files.common.printer import Printer
from slips_files.core.database.redis_db.database import RedisDB
from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.structures.evidence import Evidence
from slips_files.core.structures.alerts import Alert
from slips_files.core.output import Output


class DBManager:
    """
    This class will be calling methods from the appropriate db.
    each method added to any of the dbs should have a
    handler in here
    """

    name = "DBManager"

    def __init__(
        self,
        logger: Output,
        output_dir,
        redis_port,
        start_sqlite=True,
        start_redis_server=True,
        **kwargs,
    ):
        self.output_dir = output_dir
        self.redis_port = redis_port
        self.logger = logger
        self.printer = Printer(self.logger, self.name)
        self.rdb = RedisDB(
            self.logger, redis_port, start_redis_server, **kwargs
        )

        # in some rare cases we don't wanna create the sqlite db from scratch,
        # like when using -S to stop the daemon, we just wanna connect to
        # the existing one
        self.sqlite = None
        if start_sqlite:
            self.sqlite = SQLiteDB(self.logger, output_dir)

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

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

    def is_running_non_stop(self, *args, **kwargs):
        return self.rdb.is_running_non_stop(*args, **kwargs)

    def get_flows_analyzed_per_minute(self, *args, **kwargs):
        return self.rdb.get_flows_analyzed_per_minute(*args, **kwargs)

    def get_ip_info(self, *args, **kwargs):
        return self.rdb.get_ip_info(*args, **kwargs)

    def set_new_ip(self, *args, **kwargs):
        return self.rdb.set_new_ip(*args, **kwargs)

    def store_known_fp_md5_hashes(self, *args, **kwargs):
        return self.rdb.store_known_fp_md5_hashes(*args, **kwargs)

    def is_known_fp_md5_hash(self, *args, **kwargs):
        return self.rdb.is_known_fp_md5_hash(*args, **kwargs)

    def ask_for_ip_info(self, *args, **kwargs):
        return self.rdb.ask_for_ip_info(*args, **kwargs)

    @classmethod
    def discard_obj(cls):
        """
        when connecting on multiple ports, this dbmanager since it's a
        singelton
        returns the same instance of the already used db
        to fix this, we call this function every time we find a used db
        that slips should connect to
        """
        cls._obj = None

    def update_times_contacted(self, *args, **kwargs):
        return self.rdb.update_times_contacted(*args, **kwargs)

    def update_ip_info(self, *args, **kwargs):
        return self.rdb.update_ip_info(*args, **kwargs)

    def get_slips_internal_time(self, *args, **kwargs):
        return self.rdb.get_slips_internal_time(*args, **kwargs)

    def mark_profile_as_malicious(self, *args, **kwargs):
        return self.rdb.mark_profile_as_malicious(*args, **kwargs)

    def get_malicious_profiles(self, *args, **kwargs):
        return self.rdb.get_malicious_profiles(*args, **kwargs)

    def get_asn_info(self, *args, **kwargs):
        return self.rdb.get_asn_info(*args, **kwargs)

    def get_rdns_info(self, *args, **kwargs):
        return self.rdb.get_rdns_info(*args, **kwargs)

    def get_sni_info(self, *args, **kwargs):
        return self.rdb.get_sni_info(*args, **kwargs)

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

    def get_accumulated_threat_level(self, *args, **kwargs):
        return self.rdb.get_accumulated_threat_level(*args, **kwargs)

    def update_accumulated_threat_level(self, *args, **kwargs):
        return self.rdb.update_accumulated_threat_level(*args, **kwargs)

    def set_ip_info(self, *args, **kwargs):
        return self.rdb.set_ip_info(*args, **kwargs)

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

    def get_redis_server_pid(self, *args, **kwargs):
        return self.rdb.get_redis_server_pid(*args, **kwargs)

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

    def delete_tranco_whitelist(self, *args, **kwargs):
        return self.rdb.delete_tranco_whitelist(*args, **kwargs)

    def set_growing_zeek_dir(self, *args, **kwargs):
        return self.rdb.set_growing_zeek_dir(*args, **kwargs)

    def is_growing_zeek_dir(self, *args, **kwargs):
        return self.rdb.is_growing_zeek_dir(*args, **kwargs)

    def get_ip_identification(self, *args, **kwargs):
        return self.rdb.get_ip_identification(*args, **kwargs)

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

    def get_all_zeek_files(self, *args, **kwargs):
        return self.rdb.get_all_zeek_files(*args, **kwargs)

    def get_gateway_ip(self, *args, **kwargs):
        return self.rdb.get_gateway_ip(*args, **kwargs)

    def get_gateway_mac(self, *args, **kwargs):
        return self.rdb.get_gateway_mac(*args, **kwargs)

    def get_gateway_mac_vendor(self, *args, **kwargs):
        return self.rdb.get_gateway_mac_vendor(*args, **kwargs)

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

    def set_reconnections(self, *args, **kwargs):
        return self.rdb.set_reconnections(*args, **kwargs)

    def get_host_ip(self, *args, **kwargs):
        return self.rdb.get_host_ip(*args, **kwargs)

    def set_new_incoming_flows(self, *args, **kwargs):
        return self.rdb.set_new_incoming_flows(*args, **kwargs)

    def will_slips_have_new_incoming_flows(self, *args, **kwargs):
        return self.rdb.will_slips_have_new_incoming_flows(*args, **kwargs)

    def set_host_ip(self, *args, **kwargs):
        return self.rdb.set_host_ip(*args, **kwargs)

    def set_asn_cache(self, *args, **kwargs):
        return self.rdb.set_asn_cache(*args, **kwargs)

    def get_asn_cache(self, *args, **kwargs):
        return self.rdb.get_asn_cache(*args, **kwargs)

    def store_pid(self, *args, **kwargs):
        return self.rdb.store_pid(*args, **kwargs)

    def get_pids(self, *args, **kwargs):
        return self.rdb.get_pids(*args, **kwargs)

    def set_org_info(self, *args, **kwargs):
        return self.rdb.set_org_info(*args, **kwargs)

    def get_org_info(self, *args, **kwargs):
        return self.rdb.get_org_info(*args, **kwargs)

    def get_org_ips(self, *args, **kwargs):
        return self.rdb.get_org_ips(*args, **kwargs)

    def set_whitelist(self, *args, **kwargs):
        return self.rdb.set_whitelist(*args, **kwargs)

    def get_all_whitelist(self, *args, **kwargs):
        return self.rdb.get_all_whitelist(*args, **kwargs)

    def get_whitelist(self, *args, **kwargs):
        return self.rdb.get_whitelist(*args, **kwargs)

    def has_cached_whitelist(self, *args, **kwargs):
        return self.rdb.has_cached_whitelist(*args, **kwargs)

    def is_doh_server(self, *args, **kwargs):
        return self.rdb.is_doh_server(*args, **kwargs)

    def get_analysis_info(self, *args, **kwargs):
        return self.rdb.get_analysis_info(*args, **kwargs)

    def store_dhcp_server(self, *args, **kwargs):
        return self.rdb.store_dhcp_server(*args, **kwargs)

    def is_dhcp_server(self, *args, **kwargs):
        return self.rdb.is_dhcp_server(*args, **kwargs)

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

    def get_evidence_by_id(self, *args, **kwargs):
        return self.rdb.get_evidence_by_id(*args, **kwargs)

    def is_detection_disabled(self, *args, **kwargs):
        return self.rdb.is_detection_disabled(*args, **kwargs)

    def set_flow_causing_evidence(self, *args, **kwargs):
        return self.rdb.set_flow_causing_evidence(*args, **kwargs)

    def get_flows_causing_evidence(self, *args, **kwargs):
        """returns the list of uids of the flows causing evidence"""
        return self.rdb.get_flows_causing_evidence(*args, **kwargs)

    def set_evidence(self, *args, **kwargs):
        return self.rdb.set_evidence(*args, **kwargs)

    def set_alert(
        self, alert: Alert, evidence_causing_the_alert: Dict[str, Evidence]
    ):
        """
        Sets the alert in the rdb and sqlite databases and labels each flow
        that was responsible for this alert as "malicious"
        """
        self.rdb.set_alert(alert)
        self.sqlite.add_alert(alert)

        for evidence_id in evidence_causing_the_alert.keys():
            uids: List[str] = self.rdb.get_flows_causing_evidence(evidence_id)
            self.set_flow_label(uids, "malicious")
        return

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

    def delete_evidence(self, *args, **kwargs):
        return self.rdb.delete_evidence(*args, **kwargs)

    def cache_whitelisted_evidence_id(self, *args, **kwargs):
        return self.rdb.cache_whitelisted_evidence_id(*args, **kwargs)

    def is_whitelisted_evidence(self, *args, **kwargs):
        return self.rdb.is_whitelisted_evidence(*args, **kwargs)

    def remove_whitelisted_evidence(self, *args, **kwargs):
        return self.rdb.remove_whitelisted_evidence(*args, **kwargs)

    def get_profileid_twid_alerts(self, *args, **kwargs):
        return self.rdb.get_profileid_twid_alerts(*args, **kwargs)

    def get_twid_evidence(self, *args, **kwargs):
        return self.rdb.get_twid_evidence(*args, **kwargs)

    def update_threat_level(self, *args, **kwargs):
        return self.rdb.update_threat_level(*args, **kwargs)

    def set_loaded_ti_files(self, *args, **kwargs):
        return self.rdb.set_loaded_ti_files(*args, **kwargs)

    def get_loaded_ti_feeds_number(self, *args, **kwargs):
        return self.rdb.get_loaded_ti_feeds_number(*args, **kwargs)

    def get_loaded_ti_feeds(self, *args, **kwargs):
        return self.rdb.get_loaded_ti_feeds(*args, **kwargs)

    def set_cyst_enabled(self, *args, **kwargs):
        return self.rdb.set_cyst_enabled(*args, **kwargs)

    def is_cyst_enabled(self, *args, **kwargs):
        return self.rdb.is_cyst_enabled(*args, **kwargs)

    def give_threat_intelligence(self, *args, **kwargs):
        return self.rdb.give_threat_intelligence(*args, **kwargs)

    def delete_ips_from_ioc_ips(self, *args, **kwargs):
        return self.rdb.delete_ips_from_ioc_ips(*args, **kwargs)

    def delete_domains_from_ioc_domains(self, *args, **kwargs):
        return self.rdb.delete_domains_from_ioc_domains(*args, **kwargs)

    def add_ips_to_ioc(self, *args, **kwargs):
        return self.rdb.add_ips_to_ioc(*args, **kwargs)

    def add_domains_to_ioc(self, *args, **kwargs):
        return self.rdb.add_domains_to_ioc(*args, **kwargs)

    def add_ip_range_to_ioc(self, *args, **kwargs):
        return self.rdb.add_ip_range_to_ioc(*args, **kwargs)

    def add_asn_to_ioc(self, *args, **kwargs):
        return self.rdb.add_asn_to_ioc(*args, **kwargs)

    def is_blacklisted_asn(self, *args, **kwargs):
        return self.rdb.is_blacklisted_asn(*args, **kwargs)

    def add_ja3_to_ioc(self, *args, **kwargs):
        return self.rdb.add_ja3_to_ioc(*args, **kwargs)

    def add_jarm_to_ioc(self, *args, **kwargs):
        return self.rdb.add_jarm_to_ioc(*args, **kwargs)

    def add_ssl_sha1_to_ioc(self, *args, **kwargs):
        return self.rdb.add_ssl_sha1_to_ioc(*args, **kwargs)

    def get_all_blacklisted_ip_ranges(self, *args, **kwargs):
        return self.rdb.get_all_blacklisted_ip_ranges(*args, **kwargs)

    def get_all_blacklisted_ips(self, *args, **kwargs):
        return self.rdb.get_all_blacklisted_ips(*args, **kwargs)

    def get_all_blacklisted_domains(self, *args, **kwargs):
        return self.rdb.get_all_blacklisted_domains(*args, **kwargs)

    def get_all_blacklisted_ja3(self, *args, **kwargs):
        return self.rdb.get_all_blacklisted_ja3(*args, **kwargs)

    def is_blacklisted_jarm(self, *args, **kwargs):
        return self.rdb.is_blacklisted_jarm(*args, **kwargs)

    def is_blacklisted_ip(self, *args, **kwargs):
        return self.rdb.is_blacklisted_ip(*args, **kwargs)

    def is_blacklisted_ssl(self, *args, **kwargs):
        return self.rdb.is_blacklisted_ssl(*args, **kwargs)

    def is_blacklisted_domain(self, *args, **kwargs):
        return self.rdb.is_blacklisted_domain(*args, **kwargs)

    def delete_feed_entries(self, *args, **kwargs):
        return self.rdb.delete_feed_entries(*args, **kwargs)

    def is_profile_malicious(self, *args, **kwargs):
        return self.rdb.is_profile_malicious(*args, **kwargs)

    def set_ti_feed_info(self, *args, **kwargs):
        return self.rdb.set_ti_feed_info(*args, **kwargs)

    def set_feed_last_update_time(self, *args, **kwargs):
        return self.rdb.set_feed_last_update_time(*args, **kwargs)

    def get_ti_feed_info(self, *args, **kwargs):
        return self.rdb.get_ti_feed_info(*args, **kwargs)

    def delete_ti_feed(self, *args, **kwargs):
        return self.rdb.delete_ti_feed(*args, **kwargs)

    def is_cached_url_by_vt(self, *args, **kwargs):
        return self.rdb.is_cached_url_by_vt(*args, **kwargs)

    def get_domain_data(self, *args, **kwargs):
        return self.rdb.get_domain_data(*args, **kwargs)

    def set_info_for_domains(self, *args, **kwargs):
        return self.rdb.set_info_for_domains(*args, **kwargs)

    def cache_url_info_by_virustotal(self, *args, **kwargs):
        return self.rdb.cache_url_info_by_virustotal(*args, **kwargs)

    def get_data_from_profile_tw(self, *args, **kwargs):
        return self.rdb.get_data_from_profile_tw(*args, **kwargs)

    def get_outtuples_from_profile_tw(self, *args, **kwargs):
        return self.rdb.get_outtuples_from_profile_tw(*args, **kwargs)

    def get_intuples_from_profile_tw(self, *args, **kwargs):
        return self.rdb.get_intuples_from_profile_tw(*args, **kwargs)

    def incr_msgs_received_in_channel(self, *args, **kwargs):
        return self.rdb.incr_msgs_received_in_channel(*args, **kwargs)

    def get_enabled_modules(self, *args, **kwargs):
        return self.rdb.get_enabled_modules(*args, **kwargs)

    def get_msgs_received_at_runtime(self, *args, **kwargs):
        return self.rdb.get_msgs_received_at_runtime(*args, **kwargs)

    def get_msgs_published_in_channel(self, *args, **kwargs):
        return self.rdb.get_msgs_published_in_channel(*args, **kwargs)

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

    def get_final_state_from_flags(self, *args, **kwargs):
        return self.rdb.get_final_state_from_flags(*args, **kwargs)

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
        return self.sqlite.get_all_contacted_ips_in_profileid_twid(
            *args, **kwargs
        )

    def mark_profile_and_timewindow_as_blocked(self, *args, **kwargs):
        return self.rdb.mark_profile_and_timewindow_as_blocked(*args, **kwargs)

    def get_blocked_timewindows_of_profile(self, *args, **kwargs):
        return self.rdb.get_blocked_timewindows_of_profile(*args, **kwargs)

    def get_blocked_profiles_and_timewindows(self, *args, **kwargs):
        return self.rdb.get_blocked_profiles_and_timewindows(*args, **kwargs)

    def get_used_redis_port(self):
        return self.rdb.get_used_port()

    def is_blocked_profile_and_tw(self, *args, **kwargs):
        return self.rdb.is_blocked_profile_and_tw(*args, **kwargs)

    def was_profile_and_tw_modified(self, *args, **kwargs):
        return self.rdb.was_profile_and_tw_modified(*args, **kwargs)

    def add_software_to_profile(self, *args, **kwargs):
        return self.rdb.add_software_to_profile(*args, **kwargs)

    def get_total_flows(self, *args, **kwargs):
        return int(self.rdb.get_total_flows(*args, **kwargs))

    def increment_processed_flows(self, *args, **kwargs):
        return self.rdb.increment_processed_flows(*args, **kwargs)

    def get_processed_flows_so_far(self, *args, **kwargs):
        return self.rdb.get_processed_flows_so_far(*args, **kwargs)

    def add_out_ssh(self, *args, **kwargs):
        return self.rdb.add_out_ssh(*args, **kwargs)

    def add_out_notice(self, *args, **kwargs):
        return self.rdb.add_out_notice(*args, **kwargs)

    def add_out_ssl(self, *args, **kwargs):
        return self.rdb.add_out_ssl(*args, **kwargs)

    def get_profileid_from_ip(self, *args, **kwargs):
        return self.rdb.get_profileid_from_ip(*args, **kwargs)

    def get_first_flow_time(self, *args, **kwargs):
        return self.rdb.get_first_flow_time(*args, **kwargs)

    def get_profiles(self, *args, **kwargs):
        return self.rdb.get_profiles(*args, **kwargs)

    def get_number_of_alerts_so_far(self, *args, **kwargs):
        return self.rdb.get_number_of_alerts_so_far(*args, **kwargs)

    def get_tws_from_profile(self, *args, **kwargs):
        return self.rdb.get_tws_from_profile(*args, **kwargs)

    def get_number_of_tws_in_profile(self, *args, **kwargs):
        return self.rdb.get_number_of_tws_in_profile(*args, **kwargs)

    def get_srcips_from_profile_tw(self, *args, **kwargs):
        return self.rdb.get_srcips_from_profile_tw(*args, **kwargs)

    def get_dstips_from_profile_tw(self, *args, **kwargs):
        return self.rdb.get_dstips_from_profile_tw(*args, **kwargs)

    def get_t2_for_profile_tw(self, *args, **kwargs):
        return self.rdb.get_t2_for_profile_tw(*args, **kwargs)

    def has_profile(self, *args, **kwargs):
        return self.rdb.has_profile(*args, **kwargs)

    def get_profiles_len(self, *args, **kwargs):
        return self.rdb.get_profiles_len(*args, **kwargs)

    def get_last_twid_of_profile(self, *args, **kwargs):
        return self.rdb.get_last_twid_of_profile(*args, **kwargs)

    def get_first_twid_for_profile(self, *args, **kwargs):
        return self.rdb.get_first_twid_for_profile(*args, **kwargs)

    def get_tw_of_ts(self, *args, **kwargs):
        return self.rdb.get_tw_of_ts(*args, **kwargs)

    def add_new_tw(self, *args, **kwargs):
        return self.rdb.add_new_tw(*args, **kwargs)

    def get_tw_start_time(self, *args, **kwargs):
        return self.rdb.get_tw_start_time(*args, **kwargs)

    def get_number_of_tws(self, *args, **kwargs):
        return self.rdb.get_number_of_tws(*args, **kwargs)

    def get_modified_tw_since_time(self, *args, **kwargs):
        return self.rdb.get_modified_tw_since_time(*args, **kwargs)

    def get_modified_profiles_since(self, *args, **kwargs):
        return self.rdb.get_modified_profiles_since(*args, **kwargs)

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

    def add_profile(self, *args, **kwargs):
        return self.rdb.add_profile(*args, **kwargs)

    def set_module_label_for_profile(self, *args, **kwargs):
        return self.rdb.set_module_label_for_profile(*args, **kwargs)

    def check_tw_to_close(self, *args, **kwargs):
        return self.rdb.check_tw_to_close(*args, **kwargs)

    def check_health(self):
        self.rdb.pubsub.check_health()

    def mark_profile_tw_as_closed(self, *args, **kwargs):
        return self.rdb.mark_profile_tw_as_closed(*args, **kwargs)

    def mark_profile_tw_as_modified(self, *args, **kwargs):
        return self.rdb.mark_profile_tw_as_modified(*args, **kwargs)

    def add_tuple(self, *args, **kwargs):
        return self.rdb.add_tuple(*args, **kwargs)

    def search_tws_for_flow(self, twid, uid, go_back=False):
        """
        Search for the given uid in the given twid, or the tws before
        :param go_back: how many hours back to search?
        """

        # TODO test this
        # how many tws so search back in?
        tws_to_search = float("inf")
        if go_back:
            hrs_to_search = float(go_back)
            tws_to_search = self.rdb.get_equivalent_tws(hrs_to_search)

        twid_number: int = int(twid.split("timewindow")[-1])
        while twid_number > -1 and tws_to_search > 0:
            flow = self.sqlite.get_flow(uid, twid=f"timewindow{twid_number}")

            uid = next(iter(flow))
            if flow[uid]:
                return flow

            twid_number -= 1
            # this reaches 0 when go_back is set to a number
            tws_to_search -= 1

        # uid isn't in this twid or any of the previous ones
        return {uid: None}

    def get_modules_labels_of_a_profile(self, *args, **kwargs):
        return self.rdb.get_modules_labels_of_a_profile(*args, **kwargs)

    def add_timeline_line(self, *args, **kwargs):
        return self.rdb.add_timeline_line(*args, **kwargs)

    def get_timeline_last_lines(self, *args, **kwargs):
        return self.rdb.get_timeline_last_lines(*args, **kwargs)

    def get_profiled_tw_timeline(self, *args, **kwargs):
        return self.rdb.get_profiled_tw_timeline(*args, **kwargs)

    def mark_profile_as_gateway(self, *args, **kwargs):
        return self.rdb.mark_profile_as_gateway(*args, **kwargs)

    def set_ipv6_of_profile(self, *args, **kwargs):
        return self.rdb.set_ipv6_of_profile(*args, **kwargs)

    def set_ipv4_of_profile(self, *args, **kwargs):
        return self.rdb.set_ipv4_of_profile(*args, **kwargs)

    def get_mac_vendor_from_profile(self, *args, **kwargs):
        return self.rdb.get_mac_vendor_from_profile(*args, **kwargs)

    def label_flows_causing_alert(self, evidence_ids: List[str]):
        """
        Uses sqlite and rdb
        :param evidence_ids: list of ids of evidence causing an alert
        """

    def set_mac_vendor_to_profile(self, *args, **kwargs):
        return self.rdb.set_mac_vendor_to_profile(*args, **kwargs)

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

    def create_table(self, *args, **kwargs):
        return self.sqlite.create_table(*args, **kwargs)

    def set_flow_label(self, *args, **kwargs):
        return self.sqlite.set_flow_label(*args, **kwargs)

    def get_flow(self, *args, **kwargs):
        """returns the raw flow as read from the log file"""
        return self.sqlite.get_flow(*args, **kwargs)

    def add_flow(self, flow, profileid: str, twid: str, label="benign"):
        # stores it in the db
        self.sqlite.add_flow(flow, profileid, twid, label=label)
        # handles the channels and labels etc.
        return self.rdb.add_flow(
            flow, profileid=profileid, twid=twid, label=label
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

    def get_pid_of(self, *args, **kwargs):
        return self.rdb.get_pid_of(*args, **kwargs)

    def set_max_threat_level(self, *args, **kwargs):
        return self.rdb.set_max_threat_level(*args, **kwargs)

    def update_max_threat_level(self, *args, **kwargs):
        return self.rdb.update_max_threat_level(*args, **kwargs)

    def get_name_of_module_at(self, *args, **kwargs):
        return self.rdb.get_name_of_module_at(*args, **kwargs)

    def get_evidence_detection_threshold(self, *args, **kwargs):
        return self.rdb.get_evidence_detection_threshold(*args, **kwargs)

    def get_flows_count(self, *args, **kwargs):
        return self.sqlite.get_flows_count(*args, **kwargs)

    def get_redis_pid(self, *args, **kwargs):
        return self.rdb.get_redis_pid(*args, **kwargs)

    def increment_attack_counter(self, *args, **kwargs):
        return self.rdb.increment_attack_counter(*args, **kwargs)

    def export_labeled_flows(self, *args, **kwargs):
        """
        exports the labeled flows and altflows stored in sqlite
        db to json or csv based on the config file
        """
        self.sqlite.export_labeled_flows(
            self.get_output_dir(), *args, **kwargs
        )

    def get_commit(self, *args, **kwargs):
        return self.rdb.get_commit(*args, **kwargs)

    def get_zeek_version(self, *args, **kwargs):
        return self.rdb.get_zeek_version(*args, **kwargs)

    def get_branch(self, *args, **kwargs):
        return self.rdb.get_branch(*args, **kwargs)

    def get_tw_limits(self, *args, **kwargs):
        return self.rdb.get_tw_limits(*args, **kwargs)

    def close_sqlite(self, *args, **kwargs):
        # when stopping the daemon using -S, slips doesn't start the sqlite db
        if self.sqlite:
            self.sqlite.close(*args, **kwargs)

    def close_redis_and_sqlite(self, *args, **kwargs):
        self.rdb.r.close()
        self.rdb.rcache.close()
        self.close_sqlite()

    def get_fides_ti(self, target: str):
        return self.rdb.get_fides_ti(target)

    def save_fides_ti(self, target: str, STI: str):
        self.rdb.save_fides_ti(target, STI)

    def store_connected_peers(self, peers: List[str]):
        self.rdb.store_connected_peers(peers)

    def get_connected_peers(self):
        return self.rdb.get_connected_peers()  # no data -> []

    def store_peer_trust_data(self, id: str, td: str):
        self.rdb.update_peer_td(id, td)

    def get_peer_trust_data(self, id: str):
        return self.rdb.get_peer_td(id)

    def get_all_peers_trust_data(self):
        return self.rdb.get_all_peers_td()

    def cache_network_opinion(self, target: str, opinion: dict, time: float):
        self.rdb.cache_network_opinion(target, opinion, time)

    def get_cached_network_opinion(
        self, target: str, cache_valid_seconds: int, current_time: float
    ):
        return self.rdb.get_cached_network_opinion(
            target, cache_valid_seconds, current_time
        )
