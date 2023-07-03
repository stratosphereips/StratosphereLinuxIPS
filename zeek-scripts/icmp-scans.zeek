
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

	    # global scan_summary: function(t: table[addr] of set[addr], orig: addr): interval;

        global distinct_peers_AddressScan: table[addr] of set[addr];

        # &read_expire = 1 days  &expire_func=scan_summary &redef;

        global distinct_peers_AddressMaskScan: table[addr] of set[addr];
        global distinct_peers_TimestampScan: table[addr] of set[addr];
        global distinct_peers: table[addr] of set[addr];

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


    function check_scan(orig: addr, resp: addr, icmp: icmp_info):bool
        {

            if ( !detect_scans ) {return F;}

            if ( icmp$itype==3){
                # destination unreachable, it shouldn't be considered a scan
                return F ;
            }


            local used_table: table[addr] of set[addr];

            if ( icmp$itype==8){
                used_table =  ICMP::distinct_peers_AddressScan;
            }

            if (icmp$itype==13 || icmp$itype == 14) {
                used_table = distinct_peers_TimestampScan;
            }

            if (icmp$itype==17|| icmp$itype == 18){
                used_table = distinct_peers_AddressMaskScan;
            }


            if (orig !in used_table || resp !in used_table[orig])
            {
                # whenever there's an icmp packet, update it's distinct peer table

                # if we don't have the saddr in the table, add it
                if ( orig !in used_table ) {
                        local empty_peer_set: set[addr] ;
                        used_table[orig] = empty_peer_set;
                        }

                # if it's the first time for the saddr sending an ICMP packet to the daddr,
                # add the daddr to the set
                if ( resp !in used_table[orig] )
                        add used_table[orig][resp];

               # is it a scan?
                if ( ! ICMP::shut_down_thresh_reached[orig] &&
                     orig !in ICMP::skip_scan_sources &&
                     orig !in ICMP::skip_scan_nets &&
                     |used_table[orig]| % 5 == 0 )
                        return T ;
            }
            return F ;
        }

  #  event ICMP::m_w_shut_down_thresh_reached(ip: addr)
   #     {
#
#        if (ip !in ICMP::shut_down_thresh_reached)
 #           ICMP::shut_down_thresh_reached[ip]  = T ;

  #      }

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

	if (check_scan(orig, resp, icmp))
	{

		NOTICE([$note=ICMPAddressScan, $src=orig,
			$n=|ICMP::distinct_peers_AddressScan[orig]|,
			$msg=fmt("%s performed ICMP address scan on %s hosts",
			orig, |ICMP::distinct_peers_AddressScan[orig]|)]);

       # when any ip scans 255 hosts, start counting from scratch
       if (|ICMP::distinct_peers_AddressScan[orig]|==255) {
                ICMP::distinct_peers_AddressScan[orig] = set();

       }

		#ICMP::shut_down_thresh_reached[orig] = T;
		#event ICMP::m_w_shut_down_thresh_reached(orig);
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
		if (check_scan(orig, resp, icmp))
		{
              NOTICE([$note=TimestampScan, $src=orig,
                            $n=|ICMP::distinct_peers_TimestampScan[orig]|,
                            $msg=fmt("%s performed ICMP timestamp scan on %s hosts",
                            orig, |ICMP::distinct_peers_TimestampScan[orig]|)]);

              # when any ip scans 255 hosts, start counting from scratch
              if (|ICMP::distinct_peers_TimestampScan[orig]|==255)
              {
                    ICMP::distinct_peers_TimestampScan[orig] = set();

              }

              #ICMP::shut_down_thresh_reached[orig] = T;
		}
	}

        if (icmp$itype==17|| icmp$itype == 18)
        {
                if (check_scan(orig, resp, icmp))
                {
                      NOTICE([$note=AddressMaskScan, $src=orig,
                                $n=|ICMP::distinct_peers_AddressMaskScan[orig]|,
                                $msg=fmt("%s performed ICMP address mask scan on %s hosts",
                                orig, |ICMP::distinct_peers_AddressMaskScan[orig]|)]);

                      # when any ip scans 255 hosts, start counting from scratch
                      if (|ICMP::distinct_peers_AddressMaskScan[orig]|==255)
                      {
                            ICMP::distinct_peers_AddressMaskScan[orig] = set();
                      }
                        #ICMP::shut_down_thresh_reached[orig] = T;
                }
        }
	}


event zeek_done()
    {
        #for ( orig in distinct_peers )
        #        scan_summary(distinct_peers, orig);
	}


@endif