<!-- markdownlint-disable -->

<a href="../src/wazuh.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `wazuh.py`
Wazuh operational logic. 

**Global Variables**
---------------
- **WAZUH_USER**
- **WAZUH_GROUP**
- **KNOWN_HOSTS_PATH**
- **RSA_PATH**
- **REPOSITORY_PATH**

---

<a href="../src/wazuh.py#L106"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `update_configuration`

```python
update_configuration(
    container: Container,
    indexer_ips: list[str],
    charm_addresses: list[str],
    unit_name: str,
    key: str
) → None
```

Update the charm configuration. 



**Arguments:**
 
 - <b>`container`</b>:  the container for which to update the configuration. 
 - <b>`indexer_ips`</b>:  list of indexer IPs to configure. 
 - <b>`charm_addresses`</b>:  the unit addresses. 
 - <b>`unit_name`</b>:  the unit's name. 
 - <b>`key`</b>:  the Wazuh key for the nodes. 



**Raises:**
 
 - <b>`WazuhInstallationError`</b>:  if an error occurs while installing. 


---

<a href="../src/wazuh.py#L135"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `install_certificates`

```python
install_certificates(
    container: Container,
    public_key: str,
    private_key: str,
    root_ca: str
) → None
```

Update Wazuh filebeat certificates. 



**Arguments:**
 
 - <b>`container`</b>:  the container for which to update the configuration. 
 - <b>`public_key`</b>:  the certificate's public key. 
 - <b>`private_key`</b>:  the certificate's private key. 
 - <b>`root_ca`</b>:  the certifciate's CA public key. 


---

<a href="../src/wazuh.py#L155"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `configure_agent_password`

```python
configure_agent_password(container: Container, password: str) → None
```

Configure the agent password. 



**Arguments:**
 
 - <b>`container`</b>:  the container for which to update the password. 
 - <b>`password`</b>:  the password for authenticating the agents. 


---

<a href="../src/wazuh.py#L203"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `configure_git`

```python
configure_git(
    container: Container,
    custom_config_repository: Optional[str],
    custom_config_ssh_key: Optional[str]
) → None
```

Configure git. 



**Args:**
 
 - <b>`container`</b>:  the container to configure git for. 
 - <b>`custom_config_repository`</b>:  the git repository to add to known hosts in format 
 - <b>`git+ssh`</b>: //<user>@<url>:<branch>. 
 - <b>`custom_config_ssh_key`</b>:  the SSH key for the git repository. 


---

<a href="../src/wazuh.py#L261"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `pull_configuration_files`

```python
pull_configuration_files(container: Container) → None
```

Pull configuration files from the repository. 



**Args:**
 
 - <b>`container`</b>:  the container to pull the files into. 


---

<a href="../src/wazuh.py#L293"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `configure_filebeat_user`

```python
configure_filebeat_user(
    container: Container,
    username: str,
    password: str
) → None
```

Configure the filebeat user. 



**Args:**
 
 - <b>`container`</b>:  the container to configure the user for. 
 - <b>`username`</b>:  the username. 
 - <b>`password`</b>:  the password. 


---

## <kbd>class</kbd> `NodeType`
Enum for the W<çazuh node types. 

Attrs:  WORKER: worker.  MASTER: master. 





---

## <kbd>class</kbd> `WazuhInstallationError`
Base exception for Wazuh errors. 





