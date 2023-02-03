##! gateway identification and extraction for DHCP traffic.

@load policy/protocols/conn/known-hosts
@load base/protocols/dhcp
@load base/protocols/conn
@load base/utils/directions-and-hosts

module Log_gw;

export {

        # Add a field to the known hosts log record.
        redef record Known::HostsInfo += {
            ## Indicate if the Dst of the connection is the gw address
            is_gw: bool &default=F &log;
        };


};

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
	{

	# The ?$ operator can be used to check if a record field has a value or not
    #(it returns  T if the field has a value, and F if not).
	if ( msg?$giaddr )
		{
        Log::write(Known::HostsInfo, [ts=ts, $host=msg?$giaddr, is_gw=T]);

		}
    }