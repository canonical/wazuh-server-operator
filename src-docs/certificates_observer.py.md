<!-- markdownlint-disable -->

<a href="../src/certificates_observer.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `certificates_observer.py`
The Certificates relation observer. 

**Global Variables**
---------------
- **RELATION_NAME**


---

## <kbd>class</kbd> `CertificatesObserver`
The Certificates relation observer. 



**Attributes:**
 
 - <b>`private_key`</b>:  the private key for the certificates. 
 - <b>`csr`</b>:  the certificate signing request. 

<a href="../src/certificates_observer.py#L26"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `__init__`

```python
__init__(charm: CharmBaseWithState)
```

Initialize the observer and register event handlers. 



**Args:**
 
 - <b>`charm`</b>:  The parent charm to attach the observer to. 


---

#### <kbd>property</kbd> csr

Fetch the certificate signing request. 

Returns: the certificate signing request. 

---

#### <kbd>property</kbd> model

Shortcut for more simple access the model. 

---

#### <kbd>property</kbd> private_key

Fetch the private key. 

Returns: the private key. 




