# Retain each address record's owner; the question is not its owner.
@load base/protocols/dns

redef record DNS::Info += {
    slips_mdns_bindings: vector of string &log &optional;
};

hook DNS::do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string) &priority=0
    {
    if ( c$id$orig_p != 5353/udp && c$id$resp_p != 5353/udp )
        return;
    if ( ! msg$QR || ! c?$dns || ans$TTL <= 0secs ||
         (ans$qtype != 1 && ans$qtype != 28) )
        return;
    if ( ! (/\.local\.?$/ in to_lower(ans$query)) )
        return;
    if ( ! c$dns?$slips_mdns_bindings )
        c$dns$slips_mdns_bindings = vector();
    if ( |c$dns$slips_mdns_bindings| < 64 )
        c$dns$slips_mdns_bindings += fmt("%s|%s", to_lower(ans$query), reply);
    }
