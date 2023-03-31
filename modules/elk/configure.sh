#!/bin/bash

# Check if Elasticsearch is already configured
if ! grep -q "network.host: 127.0.0.1" /etc/elasticsearch/elasticsearch.yml; then
  # Configure Elasticsearch to listen only on the localhost
  sudo sed -i 's/#network.host: 192.168.0.1/network.host: 127.0.0.1/' /etc/elasticsearch/elasticsearch.yml
fi

# Check if Logstash is already configured
if [ ! -f /etc/logstash/conf.d/myconfig.conf ]; then
  # Create a Logstash configuration file to receive messages
  sudo bash -c 'cat > /etc/logstash/conf.d/myconfig.conf <<EOF
input {
  tcp {
    port => 5000
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "myindex-%{+YYYY.MM.dd}"
  }
}
EOF'
fi

# Check if Kibana is already configured
if ! grep -q "server.host: 127.0.0.1" /etc/kibana/kibana.yml || \
   ! grep -q "elasticsearch.hosts:" /etc/kibana/kibana.yml || \
   ! grep -q "\s* - http://localhost:9200" /etc/kibana/kibana.yml; then
  # Configure Kibana to connect to Elasticsearch on localhost only
  sudo sed -i 's/#server.host: "localhost"/server.host: "127.0.0.1"/' /etc/kibana/kibana.yml
  sudo sed -i 's/#elasticsearch.hosts:/elasticsearch.hosts:/' /etc/kibana/kibana.yml
  sudo sed -i 's/#\s* - http:\/\/localhost:9200/    - http:\/\/localhost:9200/' /etc/kibana/kibana.yml
fi
