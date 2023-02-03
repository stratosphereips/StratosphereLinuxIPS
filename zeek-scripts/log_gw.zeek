###! This script adds the gateway IP information to the dhcp logs
## it adds a is_gw_dst parameter to each dhcp flow that is set to true when the server_addr is the gateway

@load policy/protocols/conn/known-hosts
@load base/protocols/dhcp
@load base/protocols/conn
@load base/utils/directions-and-hosts

module Log_gw;


export {
        redef record DHCP::Info +=
{
                # The name of the new field will be orig_mac_oui
                is_gw_dst: bool &default=F &log;
        };
}

# Add the giaddr to DHCP::Info

# DHCP::aggregate_msgs is used to distribute data around clusters.
# In this case, this event is used to extend the DHCP logs.

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string,
	is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) {
	if ( msg?$giaddr ) {
		    DHCP::log_info$is_gw_dst = T;
    	}
	}