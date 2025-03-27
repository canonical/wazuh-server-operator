# How to collect remote logs

This charmed version of Wazuh is configured to support logs collection from remote systems.

Logs are sent from remote servers to Wazuh over a mutual TLS connection on port 6514.

The mutual TLS connection ensures that both the client and the server are identified to each other (no machine in the middle attack or unauthorized clients).

## Configure the server

Provide the certification authority (CA) certificate used to sign the client certificates to the charm with the `logs-certification-authority` configuration option. For instance: `juju config wazuh-server logs-certification-authority="$(cat ca.pem)"` where `ca.pem` contains your CA certificate.

## Configure the clients

Generate a certificate for the client with your certification authority (the same one you configured in the previous section). It will be used to authenticate the client when sending logs to the server.

Deploy the server CA on the client so that the client can trust the server:

- Retrieve the CA from self-signed-certificates with `juju run certificates/0 get-ca-certificate`
- Store it on the client, for instance in `/etc/rsyslog.d/wazuh-ca.pem`

Add the following configuration to `rsyslog` to support mutual TLS:

```text
$DefaultNetstreamDriver gtls
$DefaultNetstreamDriverCAFile /etc/rsyslog.d/wazuh-ca.pem
$DefaultNetstreamDriverCertFile /etc/rsyslog.d/client-cert.pem
$DefaultNetstreamDriverKeyFile /etc/rsyslog.d/client-key.pem
```

Add the following configuration to send all logs over the TLS connection:
```text
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
