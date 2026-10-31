##! Add bounded file-action metadata and retain only authentication command failures.

@load base/protocols/smb
@load policy/protocols/smb/log-cmds

module SMB;

export {
    const slips_log_file_operations = T &redef;
    const slips_log_authentication_failures = T &redef;
    redef record FileInfo += {
        slips_event_ts: time &log &optional;
        slips_file_id: string &log &optional;
        slips_write_seen: bool &log &default=F;
        slips_read_seen: bool &log &default=F;
    };
}

redef logged_file_actions += { FILE_READ, FILE_WRITE, FILE_CLOSE };

hook log_policy_files(rec: SMB::FileInfo, id: Log::ID, filter: Log::Filter)
    {
    if ( ! rec?$action )
        return;
    if ( rec$action in set(FILE_READ, FILE_WRITE, FILE_CLOSE) && ! slips_log_file_operations )
        break;
    rec$slips_event_ts = network_time();
    if ( rec?$fid )
        rec$slips_file_id = fmt("%s:%d:%.6f", rec$uid, rec$fid, time_to_double(rec$ts));
    # Only one READ and one WRITE record per file handle, not per data chunk.
    if ( rec$action == FILE_WRITE )
        {
        if ( rec$slips_write_seen )
            break;
        rec$slips_write_seen = T;
        }
    else if ( rec$action == FILE_READ )
        {
        if ( rec$slips_read_seen )
            break;
        rec$slips_read_seen = T;
        }
    }

hook log_policy(rec: SMB::CmdInfo, id: Log::ID, filter: Log::Filter)
    {
    if ( ! slips_log_authentication_failures )
        break;
    if ( rec$command !in set("SESSION_SETUP", "SESSION_SETUP_ANDX") )
        break;
    if ( ! rec?$status || rec$status in set("SUCCESS", "MORE_PROCESSING_REQUIRED", "PENDING") )
        break;
    }
