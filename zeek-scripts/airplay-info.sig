signature slips-airplay-info {
  ip-proto == tcp
  tcp-state established,originator
  payload /GET \/info\?txtAirPlay&txtRAOP RTSP\/1\.0/
  event slips_airplay_info
}
