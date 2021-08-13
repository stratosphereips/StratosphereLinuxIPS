module ARP;

export {
redef enum Log::ID += { LOG };

type Info: record {
				## Timestamp
				ts: time &log;
				## The requestor's MAC address.
				src_mac: string &log &optional;
        ## The responder's MAC address.
				mac_dst: string &log &optional;
        ## Source Protocol Address
        SPA:            addr        &log &optional;
        ## Source Hardware Address
        TPA:            addr        &log &optional;
};

global log_sensato_combined: event(rec: Info);
}

redef record connection += {
arp: Info &optional;
};

event zeek_init() &priority=5
{
  Log::create_stream(ARP::LOG, [$columns=ARP::Info, $path="arp"]);
}

function set_session(c: connection)
{
  if ( ! c?$arp) {
    add c$service["arp"];
    local info: ARP::Info;
    info$ts = network_time();
    c$arp = info;
  }
}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) &priority=5
{
    local info: Info;
		info$ts        = network_time();
		info$src_mac   = mac_src;
		info$mac_dst   = mac_dst;
		info$SPA       = SPA;
		info$TPA       = TPA;
{
    Log::write(ARP::LOG, info);
  }
}
