# This script adds the gateway IP information to the dhcp logs, it adds a notice.log entry if the gw address is identified

@load policy/protocols/conn/known-hosts
@load base/protocols/dhcp
@load base/protocols/conn
@load base/utils/directions-and-hosts

module Log_gw;


export {
        redef enum Notice::Type += {
            Gateway_addr_identified,
    };
}

# DHCP::aggregate_msgs is used to distribute data around clusters.
# In this case, this event is used to extend the DHCP logs.

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string,
	is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) {

	    # make sure that there is a giaddr field in the dhcp msg
	    if (msg?$giaddr){

	        # make sure the addr isn't 0.0.0.0
            if ( fmt("%s", msg$giaddr) != "0.0.0.0" ) {

                NOTICE([$note=Gateway_addr_identified,
                        $msg=fmt("Gateway address identified: %s ", msg$giaddr),
                        $id=id,
                        $uid=uid]);

            }
        }
    }

