# Integrate with OpenCTI

Wazuh allows integration with [OpenCTI](https://charmhub.io/opencti) through the [`opencti-connector` interface](https://charmhub.io/opencti/integrations#opencti-connector). This enables you to create [custom integration scripts](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html#custom-integration) that query OpenCTI from Wazuh. 

## What you’ll do

- Integrate `wazuh-server` charm with the `opencti` charm.
- Create a sample custom integration script to query OpenCTI from Wazuh.

## What you'll need

- An existing `wazuh-server` deployment. Refer to the [Wazuh tutorial](https://charmhub.io/wazuh-server/docs/tutorial-getting-started) on how to deploy Wazuh.
- An existing `opencti` deployment. Refer to the [OpenCTI tutorial](https://charmhub.io/opencti/docs/tutorial-getting-started) on the deployment steps.

## Integrate OpenCTI with Wazuh

Create an offer from OpenCTI:

```bash
juju offer opencti:opencti-connector opencti
```

Grant the Wazuh model access to the OpenCTI offer:

```bash
juju grant <wazuh-model> consume admin/<opencti-model>.opencti
```

In the Wazuh model, consume the OpenCTI offer:
```bash
juju switch <wazuh-model>
juju consume admin/<opencti-model>.opencti
```

Integrate Wazuh with OpenCTI:
```bash
juju integrate wazuh-server:opencti-connector admin/<opencti-model>.opencti
```

[note]
There is currently a limitation in Juju that only the offer side of a cross model relation can 
share a Juju secret to the other side. Since the OpenCTI charm creates a secret and shares it 
in the relation data, the Juju offer must be created on OpenCTI model's side and consumed by
the Wazuh model.
[/note]

## Create a custom integration script

Create a custom integration script with `custom-opencti-` prepended to the name of the script. The 
`custom-opencti-` prefix is required for the charm's automation to detect the right `<integration>` 
block in `ossec.conf` and inject the OpenCTI URL and token accordingly.

Add the script under `/var/ossec/integrations` in your [custom configuration repository](https://charmhub.io/wazuh-server/docs/how-to-configure). 

Assign permissions to the custom integration script to ensure it is executable:
```bash
chmod 750 /var/ossec/integrations/custom-opencti-script
```

Add the following configuration block to `/var/ossec/bin/ossec.conf`:

```xml
<integration>
<name>custom-opencti-script</name>
<alert_format>json</alert_format>
<api_key></api_key>
<hook_url></hook_url>
</integration>
```

Update the `wazuh-server` configuration to point to a Git reference that includes 
your custom script and configuration changes.
```bash
juju config wazuh-server custom-config-repository='git+ssh://git@<your-repo-url>@<new-reference>'
```

Monitor the deployment using `juju status` until the output looks similar to the following one:
```bash
App           Version  Status  Scale  Charm                     Channel        Rev  Address        Exposed  Message
certificates           active      1  self-signed-certificates  latest/stable  155  10.87.137.125  no       
traefik       2.11.0   active      1  traefik-k8s               latest/edge    233  10.87.242.226  no       Serving at 10.142.2.62
wazuh-server           active      1  wazuh-server              latest/edge     39  10.87.248.244  no     
```

Ensure the `wazuh-server` application reaches an `Active` status.

Congratulations! You've successfully configured custom OpenCTI integration scripts in Wazuh.