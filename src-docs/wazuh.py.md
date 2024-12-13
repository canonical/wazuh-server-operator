<!-- markdownlint-disable -->

<a href="../src/wazuh.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `wazuh.py`
Wazuh operational logic. 

**Global Variables**
---------------
- **CONTAINER_NAME**
- **KNOWN_HOSTS_PATH**
- **RSA_PATH**
- **REPOSITORY_PATH**
- **WAZUH_GROUP**
- **WAZUH_USER**

---

<a href="../src/wazuh.py#L118"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="../src/wazuh.py#L147"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="../src/wazuh.py#L167"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `configure_agent_password`

```python
configure_agent_password(container: Container, password: str) → None
```

Configure the agent password. 



**Arguments:**
 
 - <b>`container`</b>:  the container for which to update the password. 
 - <b>`password`</b>:  the password for authenticating the agents. 


---

<a href="../src/wazuh.py#L222"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="../src/wazuh.py#L280"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `pull_configuration_files`

```python
pull_configuration_files(container: Container) → None
```

Pull configuration files from the repository. 



**Args:**
 
 - <b>`container`</b>:  the container to pull the files into. 


---

<a href="../src/wazuh.py#L312"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="../src/wazuh.py#L368"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `authenticate_user`

```python
authenticate_user(username: str, password: str) → str
```

Authenticate an API user. 



**Args:**
 
 - <b>`username`</b>:  the username. 
 - <b>`password`</b>:  the password for the user. 

Returns: the JWT token 



**Raises:**
 
 - <b>`WazuhAuthenticationError`</b>:  if an authentication error occurs. . 


---

<a href="../src/wazuh.py#L403"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `change_api_password`

```python
change_api_password(username: str, password: str, token: str) → None
```

Change Wazuh's API password for a given user. 



**Args:**
 
 - <b>`username`</b>:  the username to change the user for. 
 - <b>`password`</b>:  the new password for the user. 
 - <b>`token`</b>:  the auth token for the API. 



**Raises:**
 
 - <b>`WazuhInstallationError`</b>:  if an error occurs while processing the requests. 


---

<a href="../src/wazuh.py#L443"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `generate_api_password`

```python
generate_api_password() → str
```

Generate a password that complies with the API password imposed by Wazuh. 

Returns: a string with a compliant password. 


---

<a href="../src/wazuh.py#L459"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `create_readonly_api_user`

```python
create_readonly_api_user(username: str, password: str, token: str) → None
```

Create a new readonly user for Wazuh's API. 



**Args:**
 
 - <b>`username`</b>:  the username for the user. 
 - <b>`password`</b>:  the password for the user. 
 - <b>`token`</b>:  the auth token for the API. 



**Raises:**
 
 - <b>`WazuhInstallationError`</b>:  if an error occurs while processing the requests. 


---

<a href="../src/wazuh.py#L512"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_version`

```python
get_version(container: Container) → str
```

Get the Wazuh version. 



**Arguments:**
 
 - <b>`container`</b>:  the container in which to check the version. 

Returns: the Wazuh version number. 


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





