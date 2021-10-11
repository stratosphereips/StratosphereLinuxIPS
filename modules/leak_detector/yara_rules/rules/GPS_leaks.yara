rule NETWORK_gps_location_leaked {
   meta:
      description = "Detects GPS leaked"
      author = "Veronica Valeros"
      organization = "Civilsphere Project"
      reference = ""
      date = "2021-10-10"
   strings:
      $rgx_gps_lat = /(lat|latitude){1}(\":|=){1}(-){0,1}\d{1,3}(.){1}\d{2,16}/i
      $rgx_gps_lon = /(lon|lng|long|longitude){1}(\":|=){1}(-){0,1}\d{1,3}(.){1}\d{2,16}/i
      $rgx_gps_loc = /(locations|ll|q|latlon|path){1}(\":|=){1}(-){0,1}\d{1,3}(.){1}\d{2,16}(,){1}(-){0,1}\d{1,3}(.){1}\d{2,16}/i
   condition:
      ($rgx_gps_lat and $rgx_gps_lon) or $rgx_gps_loc
}