#!/bin/bash
#/C=UA/ST=Khm/L=Hyphy/O=Digital/CN=ekk

function generateCA() {

  mkdir -p certs

  openssl genrsa -out certs/root-ca.key
  openssl req -new -key certs/root-ca.key -out certs/root-ca.csr -subj "$CERT_STRING/CN=ekk"

  {
    echo "[ekk-root-ca]"
    echo "basicConstraints = critical,CA:TRUE,pathlen:1"
    echo "keyUsage = critical, nonRepudiation, cRLSign, keyCertSign"
    echo "subjectKeyIdentifier=hash"
  } >certs/root-ca.cnf

  openssl x509 -req -days 3650 -in certs/root-ca.csr -signkey certs/root-ca.key -out certs/root-ca.crt -extfile certs/root-ca.cnf -extensions ekk-root-ca
}

function generateelasticcert() {

  openssl genrsa -out certs/elasticsearch.key

  openssl req -new -key certs/elasticsearch.key -out certs/elasticsearch.csr -subj "$CERT_STRING/CN=elasticsearch"

  {
    echo "[elasticsearch]"
    echo "authorityKeyIdentifier=keyid,issuer"
    echo "basicConstraints = critical,CA:FALSE"
    echo "extendedKeyUsage=serverAuth,clientAuth"
    echo "keyUsage = critical, digitalSignature, keyEncipherment"
    #echo "subjectAltName = DNS:elasticsearch, IP:127.0.0.1"
    echo "subjectAltName = DNS:elasticsearch, IP:127.0.0.1, DNS:$logstashcn, IP: $logstaship"
    echo "subjectKeyIdentifier=hash"
  } >certs/elasticsearch.cnf

  openssl x509 -req -days 750 -in certs/elasticsearch.csr -CA certs/root-ca.crt -CAkey certs/root-ca.key -CAcreateserial -out certs/elasticsearch.crt -extfile certs/elasticsearch.cnf -extensions elasticsearch
  mv certs/elasticsearch.key certs/elasticsearch.key.pem && openssl pkcs8 -in certs/elasticsearch.key.pem -topk8 -nocrypt -out certs/elasticsearch.key
}

function generatekibanacert() {

  openssl genrsa -out certs/kibana.key

  openssl req -new -key certs/kibana.key -out certs/kibana.csr -subj "$CERT_STRING/CN=kibana"

  {
    echo "[kibana]"
    echo "authorityKeyIdentifier=keyid,issuer"
    echo "basicConstraints = critical,CA:FALSE"
    echo "extendedKeyUsage=serverAuth"
    echo "keyUsage = critical, digitalSignature, keyEncipherment"
    #echo "subjectAltName = DNS:$logstashcn, IP: $logstaship"
    echo "subjectAltName = DNS:kibana, IP:127.0.0.1, DNS:$logstashcn, IP: $logstaship"
    echo "subjectKeyIdentifier=hash"
  } >certs/kibana.cnf

  openssl x509 -req -days 750 -in certs/kibana.csr -CA certs/root-ca.crt -CAkey certs/root-ca.key -CAcreateserial -out certs/kibana.crt -extfile certs/kibana.cnf -extensions kibana
  mv certs/kibana.key certs/kibana.key.pem && openssl pkcs8 -in certs/kibana.key.pem -topk8 -nocrypt -out certs/kibana.key
}

function generatebrokercert() {

  mkdir -p broker_certs

  openssl req -new -x509 -keyout broker_certs/kafka-ca.key -out broker_certs/kafka-ca.crt -days 3650 -subj "$CERT_STRING/CN=kafka-root-ca"

  keytool -keystore broker_certs/broker_truststore.jks -import -file broker_certs/kafka-ca.crt -alias kafka-root-ca -storepass changeit -keypass changeit -noprompt

  keytool -keystore broker_certs/broker_keystore.jks -alias broker -keyalg RSA -validity 365 -genkey -storepass changeit -keypass changeit -dname "C=UA,ST=Khm,L=Hyphy,O=Digital,CN=broker" -ext SAN=DNS:broker

  keytool -keystore broker_certs/broker_keystore.jks -alias broker -certreq -file broker_certs/broker-unsigned.crt -storepass changeit -keypass changeit -noprompt

  openssl x509 -req -CA broker_certs/kafka-ca.crt -CAkey broker_certs/kafka-ca.key -in broker_certs/broker-unsigned.crt -out broker_certs/broker.crt -days 365 -CAcreateserial -passin pass:changeit

  keytool -keystore broker_certs/broker_keystore.jks -alias kafka-root-ca -importcert -file broker_certs/kafka-ca.crt -storepass changeit -keypass changeit -noprompt

  keytool -keystore broker_certs/broker_keystore.jks -alias broker -importcert -file broker_certs/broker.crt -storepass changeit -keypass changeit -noprompt

  echo "changeit" > broker_certs/broker_keystore_cred.txt
  echo "changeit" > broker_certs/broker_key_cred.txt
  echo "changeit" > broker_certs/broker_truststore_cred.txt
}

function generateconnectcert() {

  mkdir -p connect_certs

  openssl genrsa -out connect_certs/connect.key

  openssl req -new -key connect_certs/connect.key -out connect_certs/connect.csr -subj "$CERT_STRING/CN=kafka-connect"

  {
    echo "[server]"
    echo "authorityKeyIdentifier=keyid,issuer"
    echo "basicConstraints = critical,CA:FALSE"
    echo "extendedKeyUsage=serverAuth,clientAuth"
    echo "keyUsage = critical, digitalSignature, keyEncipherment"
    #echo "subjectAltName = DNS:kafka-connect, IP:127.0.0.1"
    echo "subjectAltName = DNS:kafka-connect, IP:127.0.0.1, DNS:$logstashcn, IP: $logstaship"
    echo "subjectKeyIdentifier=hash"
  } >connect_certs/connect.cnf

  openssl x509 -req -days 750 -in connect_certs/connect.csr -CA certs/root-ca.crt -CAkey certs/root-ca.key -CAcreateserial -out connect_certs/connect.crt -extfile connect_certs/connect.cnf -extensions server
  mv connect_certs/connect.key connect_certs/connect.key.pem && openssl pkcs8 -in connect_certs/connect.key.pem -topk8 -nocrypt -out connect_certs/connect.key

  keytool -keystore connect_certs/connect.truststore.jks -import -file certs/root-ca.crt -alias ekk-root-ca -storepass changeit -noprompt
  
  keytool -keystore connect_certs/connect.truststore.jks -import -file broker_certs/kafka-ca.crt -alias kafka-root-ca -storepass changeit -noprompt

  openssl pkcs12 -export -out connect_certs/connect.p12 -in connect_certs/connect.crt -inkey connect_certs/connect.key

  keytool -destkeystore connect_certs/connect.keystore.jks -importkeystore -srckeystore connect_certs/connect.p12 -srcstoretype PKCS12

}

function generatepasswords() {

  elastic_user_pass=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 32 | head -n 1)
  kibana_system_pass=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 32 | head -n 1)
  es_sink_connector_pass=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 32 | head -n 1)
  kibanakey=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 42 | head -n 1)
}

function configuredocker() {
  sysctl -w vm.max_map_count=262144
  SYSCTL_STATUS=$(grep vm.max_map_count /etc/sysctl.conf)
  if [ "$SYSCTL_STATUS" == "vm.max_map_count=262144" ]; then
    echo "SYSCTL already configured"
  else
    echo "vm.max_map_count=262144" >>/etc/sysctl.conf
  fi

  sed -i "s/insertkibanapasswordhere/$kibana_system_pass/g" /opt/EKK/docker-compose.yml

  sed -i "s/kibanakey/$kibanakey/g" /opt/EKK/docker-compose.yml

  sed -i "s/insertpublicurlhere/https:\/\/$logstashcn/g" /opt/EKK/docker-compose.yml
}


function deploylme() {
  docker compose up -d
}

function setroles() {
  echo -e "\n\e[32m[X]\e[0m Setting es_sink_connector role"
  curl --cacert certs/root-ca.crt --user "elastic:$elastic_user_pass" -X POST "https://127.0.0.1:9200/_security/role/es_sink_connector" -H 'Content-Type: application/json' -d'
{
  "indices": [
    {
      "names": [ "*" ],
      "privileges": ["create_index", "read", "write", "view_index_metadata"]
    }
  ]
}'
}

function setpasswords() {
  temp="temp"

  echo -e "\e[32m[X]\e[0m Waiting for elasticsearch to be ready"
  while [[ "$(curl --cacert certs/root-ca.crt --user elastic:${temp} -s -o /dev/null -w ''%{http_code}'' https://127.0.0.1:9200)" != "200" ]]; do
    sleep 1
  done

  echo -e "\e[32m[X]\e[0m Setting elastic user password"
  curl --cacert certs/root-ca.crt --user elastic:${temp} -X POST "https://127.0.0.1:9200/_security/user/elastic/_password" -H 'Content-Type: application/json' -d' { "password" : "'"$elastic_user_pass"'"} '

  echo -e "\n\e[32m[X]\e[0m Setting kibana system password"
  curl --cacert certs/root-ca.crt --user "elastic:$elastic_user_pass" -X POST "https://127.0.0.1:9200/_security/user/kibana_system/_password" -H 'Content-Type: application/json' -d' { "password" : "'"$kibana_system_pass"'"} '
  
  setroles

  echo -e "\n\e[32m[X]\e[0m Creating es_sink_connector user"
  curl --cacert certs/root-ca.crt --user "elastic:$elastic_user_pass" -X POST "https://127.0.0.1:9200/_security/user/es_sink_connector" -H 'Content-Type: application/json' -d'
{
  "password" : "sink_writer",
  "roles" : [ "es_sink_connector"],
  "full_name" : "Sink Connector"
  }
'

  echo -e "\n\e[32m[X]\e[0m Setting es_sink_connector password"
  curl --cacert certs/root-ca.crt --user "elastic:$elastic_user_pass" -X POST "https://127.0.0.1:9200/_security/user/es_sink_connector/_password" -H 'Content-Type: application/json' -d' { "password" : "'"$es_sink_connector_pass"'"} '
}

function configsink() {

curl -X POST https://localhost:8083/connectors -H 'Content-Type: application/json' -d \
'{
  "name": "elasticsearch-sink",
  "config": {
    "connector.class": "io.confluent.connect.elasticsearch.ElasticsearchSinkConnector",
    "connection.url": "https://elasticsearch:9200",
    "name": "elasticsearch-sink",
    "value.converter": "org.apache.kafka.connect.json.JsonConverter",
    "value.converter.schemas.enable": "false"
    "connection.username": "es_sink_connector",
    "connection.password": "'"$es_sink_connector_pass"'",
    "elastic.security.protocol": "SSL",
    "elastic.https.ssl.keystore.location": "sink_certs/connect_keystore.jks",
    "elastic.https.ssl.keystore.password": "changeit",
    "elastic.https.ssl.keystore.type": "JKS", 
    "elastic.https.ssl.key.password": "changeit",
    "elastic.https.ssl.truststore.location": "sink_certs/connect_truststore.jks",
    "elastic.https.ssl.truststore.password": "changeit",
    "elastic.https.ssl.truststore.type": "JKS",
    "elastic.https.ssl.protocol": "TLS"
  }
}'
}


function install() {
  echo -e "Compose config"
  read -e -p "Proceed ([y]es/[n]o):" -i "y" check

  if [ "$check" == "n" ]; then
    return 1
  fi

  #move configs
  echo -e "\e[31m[!]\e[0m Duplicationg config."
  cp docker-compose-stack.yml docker-compose.yml

  #get interface name of default route
  DEFAULT_IF="$(route | grep '^default' | grep -o '[^ ]*$')"
  #get ip of the interface
  EXT_IP="$(/sbin/ifconfig "$DEFAULT_IF" | awk -F ' *|:' '/inet /{print $3}')"
  read -e -p "Enter the IP of this Linux server: " -i "$EXT_IP" logstaship
  read -e -p "Enter the Fully Qualified Domain Name (FQDN) of this Linux server. This needs to be resolvable from machines you want to communicate with: " logstashcn
  read -e -p "This script will use self signed certificates for communication and encryption. Do you want to continue with self signed certificates? ([y]es/[n]o): " -i "y" selfsignedyn

  #make certs
  generateCA
  generateelasticcert
  generatekibanacert
  generatebrokercert
  generateconnectcert
  sudo chmod -R 777 /opt/EKK/scripts
  mkdir -p clusterID
  sudo chmod -R 777 /opt/EKK/clusterID
  sudo chmod -R 777 /opt/EKK/connect-plugins
  sudo chmod -R 777 /opt/EKK/connect_certs
  sudo chmod -R 777 /opt/EKK/broker_certs
  sudo chmod -R 777 /opt/EKK/certs
  mkdir -p broker_data
  sudo chmod -R 777 /opt/EKK/broker_data

  generatepasswords
  configuredocker

  deploylme
  setpasswords

  #sink connect
  configsink

  #fix readability: 
  #fixreadability

  echo ""
  echo "##################################################################################"
  echo "## Kibana/Elasticsearch Credentials are (these will not be accessible again!)"
  echo "##"
  echo "## Web Interface login:"
  echo "## elastic:$elastic_user_pass"
  echo "##"
  echo "## System Credentials"
  echo "## kibana:$kibana_system_pass"
  echo "##################################################################################"
  echo ""
}

############
#START HERE#
############
export CERT_STRING='/C=UA/ST=Khm/L=Hyphy/O=Digital'

#Check the script has the correct permissions to run
if [ "$(id -u)" -ne 0 ]; then
  echo -e "\e[31m[!]\e[0m This script must be run with root privileges"
  exit 1
fi

#Check the install location
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
if [[ "$DIR" != "/opt/EKK" ]]; then
  echo -e "\e[31m[!]\e[0m The deploy script is not currently within the correct path, please ensure that deploy.sh is located in /opt/EKK for installation"
  exit 1
fi

#Change current working directory so relative filepaths work
cd "$DIR" || exit

if [ "$1" == "install" ]; then
  install
fi