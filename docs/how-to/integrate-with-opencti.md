# Integrate with OpenCTI

Wazuh allows integration with [OpenCTI](https://charmhub.io/opencti) through the [`opencti-connector` interface](https://charmhub.io/opencti/integrations#opencti-connector). This enables the user to create [custom integration scripts](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html#custom-integration) to query OpenCTI from Wazuh. 

## What you’ll do

- Integrate `wazuh-server` charm with the `opencti` charm.
- Create a sample custom integration script to query OpenCTI from Wazuh.

## Prerequisites

- An existing `wazuh-server` deployment. Refer to the [Wazuh tutorial](https://charmhub.io/wazuh-server/docs/tutorial-getting-started) on how to deploy Wazuh.
- An existing `opencti` deployment. Refer to the [OpenCTI tutorial](https://charmhub.io/opencti/docs/tutorial-getting-started) on the deployment steps.

## Integrate OpenCTI with Wazuh

Create an offer from OpenCTI:

```bash
juju offer opencti:opencti-connector opencti
```

Grant access to the Wazuh model for the OpenCTI offer:

```bash
juju grant <wazuh-model> consume admin/<opencti-model>.opencti
```

Switch to the Wazuh model and consume the offer:
```bash
juju switch <wazuh-model>
juju consume admin/<opencti-model>.opencti
```

Integrate Wazuh with OpenCTI:
```bash
juju integrate wazuh-server:opencti-connector admin/<opencti-model>.opencti
```

<note>
There is currently a limitation in Juju that only the offer side of a cross model relation can 
share a juju secret to the other side. Since the OpenCTI charm creates a secret and shares it 
in the relation data, the Juju offer must be created on OpenCTI model's side and consumed by
the Wazuh model.
</note>

## Create a custom integration script

Create a custom integration script with `custom-opencti-` prepended to the name of the script. The
prefix is required for the automation to identify the right `<integration>` snippet in the 
Wazuh configuration file and inject the OpenCTI URL and token accordingly. 

Add the script under `/var/ossec/integrations` in your [custom configuration repository](https://charmhub.io/wazuh-server/docs/how-to-configure). 

Assign permissions to the file:
```bash
chmod 750 /var/ossec/integrations/custom-opencti-script
```

Add the following block of configuration to the `/var/ossec/bin/ossec.conf` file:

```xml
<integration>
<name>custom-opencti-script</name>
<alert_format>json</alert_format>
<api_key></api_key>
<hook_url></hook_url>
</integration>
```

Reconfigure `wazuh-server` to use a new Git reference for the custom configuration repository 
with the above-mentioned changes.
```bash
juju config wazuh-server custom-config-repository=git+ssh://git@yourepo@yournewref
```

Monitor the deployment using `juju status` until the output looks similar to the following one:
```bash
App           Version  Status  Scale  Charm                     Channel        Rev  Address        Exposed  Message
certificates           active      1  self-signed-certificates  latest/stable  155  10.87.137.125  no       
traefik       2.11.0   active      1  traefik-k8s               latest/edge    233  10.87.242.226  no       Serving at 10.142.2.62
wazuh-server           active      1  wazuh-server              latest/edge     39  10.87.248.244  no     
```

The wazuh-server must have the `Active` status.

Congratulations! You've successfully configured custom OpenCTI integration scripts in Wazuh.









