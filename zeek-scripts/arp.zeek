module ARP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
                    ## Timestamp
                    ts: time &log;
                    ## The requestor's MAC address.
                    ## The type of operation: request or reply
                    operation: string &log &optional;
                    src_mac: string &log &optional;
                    ## The responder's MAC address.
                    dst_mac: string &log &optional;
                    ## Source Protocol Address
                    orig_h:            addr        &log &optional;
                    ## Source Hardware Address
                    resp_h:            addr        &log &optional;
                    # the src arp mac addr
                    orig_hw: string &log &optional;
                    # the dst arp mac addr
                    resp_hw: string &log &optional;
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


# SPA: The sender protocol address. aka src IP (orig_h here)
# SHA: The sender hardware address. aka sender eth
# TPA: The target protocol address. aka dst IP (resp_h here)
# THA: The target hardware address. aka receiver eth
event arp_request(src_mac: string, dst_mac: string, orig_h: addr, SHA: string, resp_h: addr, THA: string) &priority=5
{
    local info: Info;
		info$ts        = network_time();
        info$operation = "request";
		info$src_mac   = src_mac;
		info$dst_mac   = dst_mac;
		info$orig_h       = orig_h;
		info$resp_h       = resp_h;
        info$orig_hw      = SHA;
        info$resp_hw      = THA;

    Log::write(ARP::LOG, info);

}


event arp_reply(src_mac: string, dst_mac: string, orig_h: addr, SHA: string, resp_h: addr, THA: string)
{
    local info: Info;
        info$ts        = network_time();
        info$operation = "reply";
        info$src_mac   = src_mac;
        info$dst_mac   = dst_mac;
        info$orig_h       = orig_h;
        info$resp_h       = resp_h;
        info$orig_hw      = SHA;
        info$resp_hw      = THA;

    Log::write(ARP::LOG, info);
}