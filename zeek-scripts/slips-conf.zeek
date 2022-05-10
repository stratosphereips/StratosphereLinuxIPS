redef LogAscii::use_json=T;
redef Log::default_rotation_interval=1hr;

event reporter_error(t: time , msg: string , location: string )
{
	print fmt ("EVENT: Reporter ERROR: %s, %s, %s.", t, msg, location);
	if (/disappeared/ in msg)
	{
        terminate();
	}
}

# known-services will only consider local networks.
redef Site::local_nets += { 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8 };
# zeek needs to know where maxmind db is. mmdb_dir should now be slips/databases
redef mmdb_dir = fmt("%s%s", rstrip(@DIR, "zeek-scripts/."), "/databases");
