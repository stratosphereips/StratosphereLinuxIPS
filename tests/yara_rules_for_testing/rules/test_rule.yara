rule Test_rule {
   meta:
      description = "This rule is used for testing, it matches all pcaps"
      author = "John Doe"
      organization = ""
      reference = ""
      date = "2021-10-10"
   strings:
      $pcap_magic_bytes = { D4 C3 B2 A1 }
   condition:
      $pcap_magic_bytes
}