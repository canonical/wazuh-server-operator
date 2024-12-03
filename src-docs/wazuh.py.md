<!-- markdownlint-disable -->

<a href="../src/wazuh.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `wazuh.py`
Wazuh operational logic. 

**Global Variables**
---------------
- **KNOWN_HOSTS_PATH**
- **RSA_PATH**
- **REPOSITORY_PATH**
- **WAZUH_GROUP**
- **WAZUH_USER**

---

<a href="../src/wazuh.py#L117"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `update_configuration`

```python
update_configuration(
    container: Container,
    indexer_ips: list[str],
    charm_addresses: list[str],
    unit_name: str,
    cluster_key: str
) → None
```

Update the workload configuration. 



**Arguments:**
 
 - <b>`container`</b>:  the container for which to update the configuration. 
 - <b>`indexer_ips`</b>:  list of indexer IPs to configure. 
 - <b>`charm_addresses`</b>:  the unit addresses. 
 - <b>`unit_name`</b>:  the unit's name. 
 - <b>`cluster_key`</b>:  the Wazuh key for the cluster nodes. 



**Raises:**
 
 - <b>`WazuhInstallationError`</b>:  if an error occurs while installing. 


---

<a href="../src/wazuh.py#L146"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="../src/wazuh.py#L166"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `configure_agent_password`

```python
configure_agent_password(container: Container, password: str) → None
```

Configure the agent password. 



**Arguments:**
 
 - <b>`container`</b>:  the container for which to update the password. 
 - <b>`password`</b>:  the password for authenticating the agents. 


---

<a href="../src/wazuh.py#L221"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="../src/wazuh.py#L279"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `pull_configuration_files`

```python
pull_configuration_files(container: Container) → None
```

Pull configuration files from the repository. 



**Args:**
 
 - <b>`container`</b>:  the container to pull the files into. 


---

<a href="../src/wazuh.py#L311"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="../src/wazuh.py#L367"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `change_api_password`

```python
change_api_password(username: str, old_password: str, new_password: str) → None
```

Change Wazuh's API password for a given user. 



**Args:**
 
 - <b>`username`</b>:  the username to change the user for. 
 - <b>`old_password`</b>:  the old API password for the user. 
 - <b>`new_password`</b>:  the new API password for the user. 



**Raises:**
 
 - <b>`WazuhAuthenticationError`</b>:  if an authentication error occurs. 
 - <b>`WazuhInstallationError`</b>:  if an error occurs while processing the requests. 


---

<a href="../src/wazuh.py#L431"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `generate_api_credentials`

```python
generate_api_credentials() → dict[str, str]
```

Generate the credentials for the default API users. 

Returns: a dict containing the new credentials. 


---

## <kbd>class</kbd> `NodeType`
Enum for the Wazuh node types. 

Attrs:  WORKER: worker.  MASTER: master. 





---

## <kbd>class</kbd> `WazuhAuthenticationError`
Wazuh authentication errors. 





---

## <kbd>class</kbd> `WazuhInstallationError`
Base exception for Wazuh errors. 





