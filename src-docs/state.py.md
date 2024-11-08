<!-- markdownlint-disable -->

<a href="../src/state.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `state.py`
Wazuh server charm state. 



---

## <kbd>class</kbd> `CharmBaseWithState`
CharmBase than can build a CharmState. 


---

#### <kbd>property</kbd> app

Application that this unit is part of. 

---

#### <kbd>property</kbd> charm_dir

Root directory of the charm as it is running. 

---

#### <kbd>property</kbd> config

A mapping containing the charm's config and current values. 

---

#### <kbd>property</kbd> meta

Metadata of this charm. 

---

#### <kbd>property</kbd> model

Shortcut for more simple access the model. 

---

#### <kbd>property</kbd> unit

Unit that this execution is responsible for. 



---

<a href="../src/state.py#L22"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `reconcile`

```python
reconcile() → None
```

Reconcile configuration. 


---

## <kbd>class</kbd> `InvalidStateError`
Exception raised when a charm configuration is found to be invalid. 





---

## <kbd>class</kbd> `ProxyConfig`
Proxy configuration. 



**Attributes:**
 
 - <b>`http_proxy`</b>:  The http proxy URL. 
 - <b>`https_proxy`</b>:  The https proxy URL. 
 - <b>`no_proxy`</b>:  Comma separated list of hostnames to bypass proxy. 


---

#### <kbd>property</kbd> model_extra

Get extra fields set during validation. 



**Returns:**
  A dictionary of extra fields, or `None` if `config.extra` is not set to `"allow"`. 

---

#### <kbd>property</kbd> model_fields_set

Returns the set of fields that have been explicitly set on this model instance. 



**Returns:**
  A set of strings representing the fields that have been set,  i.e. that were not filled from defaults. 




---

## <kbd>class</kbd> `State`
The Wazuh server charm state. 



**Attributes:**
 
 - <b>`agent_password`</b>:  the agent password. 
 - <b>`indexer_ips`</b>:  list of Wazuh indexer IPs. 
 - <b>`filebeat_username`</b>:  the filebeat username. 
 - <b>`filebeat_password`</b>:  the filebeat password. 
 - <b>`certificate`</b>:  the TLS certificate. 
 - <b>`root_ca`</b>:  the CA certificate. 
 - <b>`custom_config_repository`</b>:  the git repository where the configuration is. 
 - <b>`custom_config_ssh_key`</b>:  the SSH key for the git repository. 
 - <b>`proxy`</b>:  proxy configuration. 

<a href="../src/state.py#L180"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `__init__`

```python
__init__(
    agent_password: Optional[str],
    indexer_ips: list[str],
    filebeat_username: str,
    filebeat_password: str,
    certificate: str,
    root_ca: str,
    wazuh_config: WazuhConfig,
    custom_config_ssh_key: Optional[str]
)
```

Initialize a new instance of the CharmState class. 



**Args:**
 
 - <b>`agent_password`</b>:  the agent password. 
 - <b>`indexer_ips`</b>:  list of Wazuh indexer IPs. 
 - <b>`filebeat_username`</b>:  the filebeat username. 
 - <b>`filebeat_password`</b>:  the filebeat password. 
 - <b>`certificate`</b>:  the TLS certificate. 
 - <b>`root_ca`</b>:  the CA certificate. 
 - <b>`wazuh_config`</b>:  Wazuh configuration. 
 - <b>`custom_config_ssh_key`</b>:  the SSH key for the git repository. 


---

#### <kbd>property</kbd> model_extra

Get extra fields set during validation. 



**Returns:**
  A dictionary of extra fields, or `None` if `config.extra` is not set to `"allow"`. 

---

#### <kbd>property</kbd> model_fields_set

Returns the set of fields that have been explicitly set on this model instance. 



**Returns:**
  A set of strings representing the fields that have been set,  i.e. that were not filled from defaults. 

---

#### <kbd>property</kbd> proxy

Get charm proxy configuration from juju charm environment. 



**Returns:**
  charm proxy configuration in the form of ProxyConfig. 



**Raises:**
 
 - <b>`InvalidStateError`</b>:  if the proxy configuration is invalid. 



---

<a href="../src/state.py#L236"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `from_charm`

```python
from_charm(
    charm: CharmBase,
    indexer_relation_data: dict[str, str],
    provider_certificates: list[ProviderCertificate],
    certitificate_signing_request: str
) → State
```

Initialize the state from charm. 



**Args:**
 
 - <b>`charm`</b>:  the root charm. 
 - <b>`indexer_relation_data`</b>:  the Wazuh indexer app relation data. 
 - <b>`provider_certificates`</b>:  the provider certificates. 
 - <b>`certitificate_signing_request`</b>:  the certificate signing request. 



**Returns:**
 Current state of the charm. 



**Raises:**
 
 - <b>`InvalidStateError`</b>:  if the state is invalid. 


---

## <kbd>class</kbd> `WazuhConfig`
The Wazuh server charm configuration. 



**Attributes:**
 
 - <b>`agent_password`</b>:  the secret key corresponding to the agent secret. 
 - <b>`custom_config_repository`</b>:  the git repository where the configuration is. 
 - <b>`custom_config_ssh_key`</b>:  the secret key corresponding to the SSH key for the git repository. 


---

#### <kbd>property</kbd> model_extra

Get extra fields set during validation. 



**Returns:**
  A dictionary of extra fields, or `None` if `config.extra` is not set to `"allow"`. 

---

#### <kbd>property</kbd> model_fields_set

Returns the set of fields that have been explicitly set on this model instance. 



**Returns:**
  A set of strings representing the fields that have been set,  i.e. that were not filled from defaults. 




