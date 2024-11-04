<!-- markdownlint-disable -->

<a href="../src/charm.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `charm.py`
Wazuh server charm. 

**Global Variables**
---------------
- **WAZUH_CLUSTER_KEY_SECRET_LABEL**
- **WAZUH_PEER_RELATION_NAME**


---

## <kbd>class</kbd> `WazuhServerCharm`
Charm the service. 



**Attributes:**
 
 - <b>`fqdns`</b>:  the unit FQDNs. 
 - <b>`state`</b>:  the charm state. 

<a href="../src/charm.py#L35"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `__init__`

```python
__init__(*args: Any)
```

Construct. 



**Args:**
 
 - <b>`args`</b>:  Arguments passed to the CharmBase parent constructor. 


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

#### <kbd>property</kbd> fqdns

Get the FQDNS for the charm units. 

Returns: the list of FQDNs for the charm units. 

---

#### <kbd>property</kbd> meta

Metadata of this charm. 

---

#### <kbd>property</kbd> model

Shortcut for more simple access the model. 

---

#### <kbd>property</kbd> state

The charm state. 

---

#### <kbd>property</kbd> unit

Unit that this execution is responsible for. 



---

<a href="../src/charm.py#L90"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `reconcile`

```python
reconcile() → None
```

Reconcile Wazuh configuration with charm state. 

This is the main entry for changes that require a restart. 


