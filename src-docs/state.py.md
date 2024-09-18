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

<a href="../src/state.py#L20"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `reconcile`

```python
reconcile() → None
```

Reconcile Synapse configuration. 


---

## <kbd>class</kbd> `InvalidStateError`
Exception raised when a charm configuration is found to be invalid. 





---

## <kbd>class</kbd> `State`
The Wazuh server charm state. 



**Attributes:**
 
 - <b>`indexer_ips`</b>:  list of Wazuh indexer IPs. 
 - <b>`certificate`</b>:  the TLs certificate. 


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

<a href="../src/state.py#L41"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `from_charm`

```python
from_charm(
    charm: CharmBase,
    indexer_relation_data: dict[str, str],
    certificates_relation_data: dict[str, str]
) → State
```

Initialize the state from charm. 



**Args:**
 
 - <b>`charm`</b>:  the root charm. 
 - <b>`indexer_relation_data`</b>:  the Wazuh indexer app relation data. 
 - <b>`certificates_relation_data`</b>:  the certificates relation data. 



**Returns:**
 Current state of the charm. 



**Raises:**
 
 - <b>`InvalidStateError`</b>:  if the state is invalid. 


