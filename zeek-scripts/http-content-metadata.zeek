##! Record HTTP header metadata without retaining or inspecting body bytes.

@load base/protocols/http

module HTTP;

export {
    redef record Info += {
        slips_request_content_type: string &log &optional;
        slips_response_content_type: string &log &optional;
        slips_request_content_encoding: string &log &optional;
        slips_response_content_encoding: string &log &optional;
        slips_request_headers_complete: bool &log &default=F;
        slips_response_headers_complete: bool &log &default=F;
    };
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) &priority=-5
    {
    set_state(c, is_orig);
    if ( is_orig ? c$http$slips_request_headers_complete : c$http$slips_response_headers_complete )
        return;
    # Ignore informational replies; keep the final response's headers.
    if ( ! is_orig && (! c$http?$status_code || c$http$status_code < 200) )
        return;

    local content_type = "";
    local content_encoding = "";
    for ( i in hlist )
        {
        local name = to_upper(hlist[i]$name);
        if ( name == "CONTENT-TYPE" )
            content_type = sub_bytes(hlist[i]$value, 0, 256);
        else if ( name == "CONTENT-ENCODING" )
            content_encoding = sub_bytes(hlist[i]$value, 0, 256);
        }

    if ( is_orig )
        {
        c$http$slips_request_content_type = content_type;
        c$http$slips_request_content_encoding = content_encoding;
        c$http$slips_request_headers_complete = T;
        }
    else
        {
        c$http$slips_response_content_type = content_type;
        c$http$slips_response_content_encoding = content_encoding;
        c$http$slips_response_headers_complete = T;
        }
    }
