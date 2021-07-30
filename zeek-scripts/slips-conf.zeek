redef LogAscii::use_json = T;
redef Log::default_rotation_interval=1hr;

event zeek_init()
    {
    # Replace default filter for all log files in order to
    # change the log filename.
    
    local f = Log::get_filter(Conn::LOG, "default");
    f$path = fmt("%s", strftime("conn.%Y-%m-%d", current_time()));
    Log::add_filter(Conn::LOG, f);

    f = Log::get_filter(SOCKS::LOG,"default");
    f$path = fmt("%s", strftime("socks.%Y-%m-%d", current_time()));
    Log::add_filter(SOCKS::LOG, f);
    
    f = Log::get_filter(FTP::LOG,"default");
    f$path = fmt("%s", strftime("ftp.%Y-%m-%d", current_time()));
    Log::add_filter(FTP::LOG, f);
     
    f = Log::get_filter(mysql::LOG,"default");
    f$path = fmt("%s", strftime("mysql.%Y-%m-%d", current_time()));
    Log::add_filter(mysql::LOG, f); 
    
    f = Log::get_filter(Notice::LOG,"default");
    f$path = fmt("%s", strftime("notice.%Y-%m-%d", current_time()));
    Log::add_filter(Notice::LOG, f);
    
    f = Log::get_filter(RDP::LOG,"default");
    f$path = fmt("%s", strftime("rdp.%Y-%m-%d", current_time()));
    Log::add_filter(RDP::LOG, f);
     
    f = Log::get_filter(SSH::LOG,"default");
    f$path = fmt("%s", strftime("ssh.%Y-%m-%d", current_time()));
    Log::add_filter(SSH::LOG, f);
    
    f = Log::get_filter(Syslog::LOG,"default");
    f$path = fmt("%s", strftime("syslog.%Y-%m-%d", current_time()));
    Log::add_filter(Syslog::LOG, f); 
       
    f = Log::get_filter(Tunnel::LOG,"default");
    f$path = fmt("%s", strftime("tunnel.%Y-%m-%d", current_time()));
    Log::add_filter(Tunnel::LOG, f);

    f = Log::get_filter(PE::LOG,"default");
    f$path = fmt("%s", strftime("pe.%Y-%m-%d", current_time()));
    Log::add_filter(PE::LOG, f);
    
    f = Log::get_filter(RDP::LOG,"default");
    f$path = fmt("%s", strftime("rdp.%Y-%m-%d", current_time()));
    Log::add_filter(RDP::LOG, f);
    
    f = Log::get_filter(SIP::LOG,"default");
    f$path = fmt("%s", strftime("sip.%Y-%m-%d", current_time()));
    Log::add_filter(SIP::LOG, f);
    
    f = Log::get_filter(SMTP::LOG,"default");
    f$path = fmt("%s", strftime("smtp.%Y-%m-%d", current_time()));
    Log::add_filter(SMTP::LOG, f);
    
    f = Log::get_filter(SNMP::LOG,"default");
    f$path = fmt("%s", strftime("snmp.%Y-%m-%d", current_time()));
    Log::add_filter(SNMP::LOG, f);
    
    f = Log::get_filter(SSH::LOG,"default");
    f$path = fmt("%s", strftime("ssh.%Y-%m-%d", current_time()));
    Log::add_filter(SSH::LOG, f);

    }
