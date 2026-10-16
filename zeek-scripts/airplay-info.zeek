## Tag AirPlay /info discovery before conn.log is written so Slips can
## whitelist this request without relying on a device address or port.
@load-sigs ./airplay-info.sig

event slips_airplay_info(state: signature_state, data: string)
    {
    add state$conn$service["airplay-info"];
    }
