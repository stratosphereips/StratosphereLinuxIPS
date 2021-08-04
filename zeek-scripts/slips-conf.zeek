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