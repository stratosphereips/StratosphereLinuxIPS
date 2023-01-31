##! gateway identification and extraction for DHCP traffic.

@load base/protocols/dhcp
@load base/frameworks/software
@load base/utils/directions-and-hosts

module Known;


export {
	## The known-hosts logging stream identifier.
	redef enum Log::ID += { HOSTS_LOG };

	## The record type which contains the column fields of the known-hosts log.
	type HostsInfo: record {
		## The timestamp at which the host was detected.
		ts:      time &log;
		## The address that was detected originating or responding to a
		## TCP connection.
		host:    addr &log;
	};

	## The hosts whose existence should be logged and tracked.
	## See :bro:type:`Host` for possible choices.
	const host_tracking = LOCAL_HOSTS &redef;

	## The set of all known addresses to store for preventing duplicate
	## logging of addresses.  It can also be used from other scripts to
	## inspect if an address has been seen in use.
	## Maintain the list of known hosts for 24 hours so that the existence
	## of each individual address is logged each day.
	#global known_hosts: set[addr] &create_expire=1day &synchronized &redef;

	## An event that can be handled to access the :bro:type:`Known::HostsInfo`
	## record as it is sent on to the logging framework.
	global log_known_hosts: event(rec: HostsInfo);
}





event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
	{

	# The ?$ operator can be used to check if a record field has a value or not
    #(it returns  T if the field has a value, and F if not).
	if ( msg?$giaddr )
		{
        Log::write(Known::HOSTS_LOG, [$ts=network_time(), $host=msg?$giaddr]);

		}
    }