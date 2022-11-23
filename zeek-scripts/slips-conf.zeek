redef LogAscii::use_json=T;

function get_mmdb_path(): string {
    local curdir = @DIR;
    local dbs_root_dir = fmt("%s", split_string1(curdir, /"zeek-scripts\/\."/)[0]);
    return fmt("%s%s", dbs_root_dir, "databases");
}

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
redef mmdb_dir = get_mmdb_path();
#global mmind = mmdb_dir;

# zeek  only tracks software for local networks by default to conserve memory.
# this setting makes it do software for all networks
redef Software::asset_tracking = ALL_HOSTS;