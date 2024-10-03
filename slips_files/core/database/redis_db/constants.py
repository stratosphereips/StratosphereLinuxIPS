class Constants:
    LOADED_TI_FILES = "loaded TI files"
    TI_FILES_INFO = "TI_files_info"
    GIVE_TI = "give_threat_intelligence"
    # all keys starting with IoC_* are used for storing IoCs read from
    # online and offline TI feeds
    IOC_IPS = "IoC_ips"
    IOC_DOMAINS = "IoC_domains"
    IOC_IP_RANGES = "IoC_ip_ranges"
    IOC_ASN = "IoC_ASNs"
    IOC_JA3 = "IoC_JA3"
    IOC_JARM = "IoC_JARM"
    IOC_SSL = "IoC_SSL"
    LABELED_AS_MALICIOUS = "labeled_as_malicious"
    # used to cache url info by the virustotal module only
    VT_CACHED_URL_INFO = "virustotal_cached_url_info"
    # used for Kalipso
    DOMAINS_INFO = "DomainsInfo"
    IPS_INFO = "IPsInfo"
    PROCESSED_FLOWS = "processed_flows_so_far"


class Channels:
    DNS_INFO_CHANGE = "dns_info_change"
