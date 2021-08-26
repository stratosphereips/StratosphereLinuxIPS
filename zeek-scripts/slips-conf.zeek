redef LogAscii::use_json=T;
# known-services will only consider local networks.
redef Site::local_nets += { 192.168.0.0/16 };