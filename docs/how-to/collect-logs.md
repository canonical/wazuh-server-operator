# How to collect remote logs

This charmed version of Wazuh is configured to support logs collection from remote systems.

Logs are sent from remote servers to Wazuh over a mutual TLS connection on port 6514.

The mutual TLS connection ensures that both the client and the server are identified to each other (no machine in the middle-attack, nor unauthorized clients).

## Configure the server

Provide the certification authority (CA) certificate used to sign the client certificates to the charm with the `logs-certification-authority` configuration option. For instance: `juju config wazuh-server logs-certification-authority="$(cat ca.pem)"` where `ca.pem` contains your CA certificate.

## Configure the clients

Generate a certificate for the client with your certification authority (the same as the one configured in the server in the previous section). It will be used to authenticate the client when sending logs to the server.

Deploy the server certification (CA) authority on the client so that the client can trust the server:

- Retrieve the CA from self-signed-certificates with `juju run certificates/0 get-ca-certificate`
- Store it on the client, for instance in `/etc/rsyslog.d/wazuh-ca.pem`

Configure `rsyslog` to send logs over a TLS connection:

```text
template(name="TraditionalFormat" type="string"
         string="%TIMESTAMP% %HOSTNAME% %syslogtag%%msg%\n")

$ActionFileDefaultTemplate TraditionalFormat

$DefaultNetstreamDriver gtls
$DefaultNetstreamDriverCAFile /etc/rsyslog.d/wazuh-ca.pem
$DefaultNetstreamDriverCertFile /etc/rsyslog.d/client-cert.pem
$DefaultNetstreamDriverKeyFile /etc/rsyslog.d/client-key.pem

*.* action(
type="omfwd"
target="<WAZUH_SERVER_IP>”
port="6514"
protocol="tcp"
template=”TraditionalFormat”
streamDriver="gtls"
streamDriverMode="1"
streamDriverAuthMode="x509/certvalid"
)
```
