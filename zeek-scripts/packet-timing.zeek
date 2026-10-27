##! Optional bounded timing metadata for sparse packets inside TCP connections.

@load base/protocols/conn

module SlipsPacketTiming;

export {
    redef enum Log::ID += { LOG };
    const min_events: count = 12 &redef;
    const window_events: count = 64 &redef;
    const emit_every: count = 8 &redef;
    const max_connections: count = 2048 &redef;
    const min_age: interval = 30 secs &redef;
    const min_gap: interval = 1 sec &redef;
    const min_span: interval = 60 secs &redef;
    const max_payload_bytes: count = 512 &redef;
    const include_acks: bool = F &redef;

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        kind: string &log;
        history: string &log;
        service: set[string] &log;
        times: vector of time &log;
        lengths: vector of count &log;
        event_count: count &log;
        orig_bytes: count &log;
        resp_bytes: count &log;
    };
}

type Window: record {
    times: vector of time &default=vector();
    lengths: vector of count &default=vector();
    total: count &default=0;
    logged: count &default=0;
};

type State: record {
    ends: table[bool] of count &default=table();
    windows: table[bool, string] of Window &default=table();
};

global tracked: table[string] of State &read_expire=1 hr;
global capacity_reported = F;

function write_window(c: connection, orig: bool, kind: string, w: Window)
    {
    if ( |w$times| < min_events || w$total == w$logged )
        return;
    local oldest = w$total >= window_events ? w$total % window_events : 0;
    if ( w$times[(w$total-1) % window_events] - w$times[oldest] < min_span )
        return;
    local times: vector of time;
    local lengths: vector of count;
    local start = oldest;
    for ( i in w$times )
        {
        local pos = (start + i) % window_events;
        times[i] = w$times[pos];
        lengths[i] = w$lengths[pos];
        }
    Log::write(LOG, [$ts=times[|times|-1], $uid=c$uid, $id=c$id,
        $is_orig=orig, $kind=kind, $history=c$history, $service=c$service,
        $times=times, $lengths=lengths, $event_count=w$total,
        $orig_bytes=c$orig$size, $resp_bytes=c$resp$size]);
    w$logged = w$total;
    }

event zeek_init()
    {
    Log::create_stream(LOG, [$columns=Info, $path="packet_timing"]);
    }

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count,
                 ack: count, len: count, payload: string)
    {
    if ( network_time() - c$start_time < min_age || /[SFR]/ in flags )
        return;
    if ( len == 0 && (! include_acks || /A/ !in flags) )
        return;
    if ( c$uid !in tracked )
        {
        if ( len > max_payload_bytes )
            return;
        if ( |tracked| >= max_connections )
            {
            if ( ! capacity_reported )
                {
                Reporter::warning("Packet timing collector reached max_connections; additional connections are not tracked.");
                capacity_reported = T;
                }
            return;
            }
        tracked[c$uid] = State();
        }
    local state = tracked[c$uid];
    local kind = len == 0 ? "ack" : "data";
    if ( len > 0 )
        {
        if ( is_orig in state$ends && seq + len <= state$ends[is_orig] )
            {
            if ( len > 1 || ! include_acks )
                return;
            kind = "keepalive";
            }
        else
            state$ends[is_orig] = seq + len;
        }
    if ( [is_orig, kind] !in state$windows )
        state$windows[is_orig, kind] = Window();
    local w = state$windows[is_orig, kind];
    local now = network_time();
    if ( len > max_payload_bytes || (|w$times| > 0 && now - w$times[(w$total-1) % window_events] < min_gap) )
        {
        w$times = vector();
        w$lengths = vector();
        w$total = 0;
        w$logged = 0;
        if ( len > max_payload_bytes )
            return;
        }
    w$times[w$total % window_events] = now;
    w$lengths[w$total % window_events] = len;
    ++w$total;
    if ( |w$times| >= min_events && (w$logged == 0 || w$total - w$logged >= emit_every) )
        write_window(c, is_orig, kind, w);
    }

event connection_state_remove(c: connection)
    {
    if ( c$uid !in tracked )
        return;
    for ( [orig, kind] in tracked[c$uid]$windows )
        write_window(c, orig, kind, tracked[c$uid]$windows[orig, kind]);
    delete tracked[c$uid];
    }
