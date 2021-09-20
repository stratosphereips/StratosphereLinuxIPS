module ARP;

export {
redef enum Log::ID += { LOG };

type Info: record {
				## Timestamp
				ts: time &log;
				## The requestor's MAC address.
				src_mac: string &log &optional;
        ## The responder's MAC address.
				dst_mac: string &log &optional;
        ## Source Protocol Address
        orig_h:            addr        &log &optional;
        ## Source Hardware Address
        resp_h:            addr        &log &optional;
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

event arp_request(mac_src: string, dst_mac: string, orig_h: addr, SHA: string, resp_h: addr, THA: string) &priority=5
{
    local info: Info;
		info$ts        = network_time();
		info$src_mac   = mac_src;
		info$dst_mac   = dst_mac;
		info$orig_h       = orig_h;
		info$resp_h       = resp_h;
{
    Log::write(ARP::LOG, info);
  }
}
