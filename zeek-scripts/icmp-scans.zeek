
module ICMP;

export {

        redef enum Notice::Type += {
                ICMPAddressScan,
                TimestampScan,
                AddressMaskScan,
        };

        # Whether to log detailed information icmp.log.
        const log_details = T &redef;

        # ICMP scan detection.
        const detect_scans = T &redef;
        #const scan_threshold = 25 &redef;

	    global scan_summary: function(t: table[addr] of set[addr], orig: addr): interval;

        global distinct_peers: table[addr] of set[addr]
                &read_expire = 1 days  &expire_func=scan_summary &redef;

        global shut_down_thresh_reached: table[addr] of bool &default=F;



        const skip_scan_sources = {
                255.255.255.255,        # who knows why we see these, but we do

                # AltaVista.  Here just as an example of what sort of things
                # you might list.
                #test-scooter.av.pa-x.dec.com,
        } &redef;

         const skip_scan_nets: set[subnet] = {} &redef;

        global track_icmp_echo_request : function(cid: conn_id, icmp: icmp_info ) ;

        global ICMP::w_m_icmp_echo_request: event(cid: conn_id, icmp: icmp_info) ;
        global ICMP::m_w_shut_down_thresh_reached: event(ip: addr);
        global ICMP::w_m_icmp_sent: event(c: connection, icmp: icmp_info)   ;


}


@if ( Cluster::is_enabled() )

    @if ( Cluster::local_node_type() == Cluster::MANAGER)
        event zeek_init()
                {
                Broker::auto_publish(Cluster::worker_topic, ICMP::m_w_shut_down_thresh_reached) ;
                }
    @else
        event zeek_init()
                {
                Broker::auto_publish(Cluster::manager_topic, ICMP::w_m_icmp_echo_request);
                Broker::auto_publish(Cluster::manager_topic, ICMP::w_m_icmp_sent);
                }
    @endif


@endif


@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER)

    function check_scan(orig: addr, resp: addr):bool
        {

         if ( detect_scans && (orig !in ICMP::distinct_peers || resp !in ICMP::distinct_peers[orig]) )
                    {
                    if ( orig !in ICMP::distinct_peers ) {
                            local empty_peer_set: set[addr] ;
                            ICMP::distinct_peers[orig] = empty_peer_set;
                            }

                    if ( resp !in ICMP::distinct_peers[orig] )
                            add ICMP::distinct_peers[orig][resp];

                    if ( ! ICMP::shut_down_thresh_reached[orig] &&
                         orig !in ICMP::skip_scan_sources &&
                         orig !in ICMP::skip_scan_nets &&
                         |ICMP::distinct_peers[orig]| % 5 == 0 )
                            return T ;
            }
        return F ;
        }



    event ICMP::m_w_shut_down_thresh_reached(ip: addr)
        {

        if (ip !in ICMP::shut_down_thresh_reached)
            ICMP::shut_down_thresh_reached[ip]  = T ;

        }

@endif

event icmp_echo_request(c: connection , info: icmp_info , id: count , seq: count , payload: string )
{


	#if (ICMP::shut_down_thresh_reached[icmp$orig_h])
	#	return ;

	event ICMP::w_m_icmp_echo_request(c$id, info) ;
}


@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER)

event w_m_icmp_echo_request(cid: conn_id, icmp: icmp_info)
{
	track_icmp_echo_request(cid, icmp) ;
}


function track_icmp_echo_request (cid: conn_id, icmp: icmp_info)
{
        local orig = cid$orig_h;
        local resp = cid$resp_h;

	if (check_scan(orig,resp))
	{
		NOTICE([$note=ICMPAddressScan, $src=orig,
			$n=|ICMP::distinct_peers[orig]|,
			$msg=fmt("%s performed ICMP address scan on %s hosts",
			orig, |ICMP::distinct_peers[orig]|)]);

		ICMP::shut_down_thresh_reached[orig] = T;
		event ICMP::m_w_shut_down_thresh_reached(orig);
	}


}
@endif


event icmp_sent (c: connection , info: icmp_info )
{


	event ICMP::w_m_icmp_sent (c, info) ;

}


@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER)
event ICMP::w_m_icmp_sent(c: connection, icmp: icmp_info )
	{


	local orig=c$id$orig_h ;
	local resp=c$id$resp_h ;


	if (icmp$itype==13 || icmp$itype == 14) # timestamp queries
	{
		if (check_scan(orig, resp))
		{
	              NOTICE([$note=TimestampScan, $src=orig,
                                $n=|ICMP::distinct_peers[orig]|,
                                $msg=fmt("%s performed ICMP timestamp scan on %s hosts",
                                orig, |ICMP::distinct_peers[orig]|)]);

                        ICMP::shut_down_thresh_reached[orig] = T;
		}
	}

        if (icmp$itype==17|| icmp$itype == 18)
        {
                if (check_scan(orig, resp))
                {
                      NOTICE([$note=AddressMaskScan, $src=orig,
                                $n=|ICMP::distinct_peers[orig]|,
                                $msg=fmt("%s performed ICMP address mask scan on %s hosts",
                                orig, |ICMP::distinct_peers[orig]|)]);

                        ICMP::shut_down_thresh_reached[orig] = T;
                }
        }
	}


event zeek_done()
    {
        #for ( orig in distinct_peers )
        #        scan_summary(distinct_peers, orig);
	}


@endif
