<!-- markdownlint-disable -->

<a href="../src/traefik_route_observer.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `traefik_route_observer.py`
The Traefik route relation observer. 

**Global Variables**
---------------
- **RELATION_NAME**
- **PORTS**


---

## <kbd>class</kbd> `TraefikRouteObserver`
The Traefik route relation observer. 



**Attributes:**
 
 - <b>`hostname`</b>:  The unit's hostname. 

<a href="../src/traefik_route_observer.py#L32"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `__init__`

```python
__init__(charm: CharmBase)
```

Initialize the observer and register event handlers. 



**Args:**
 
 - <b>`charm`</b>:  The parent charm to attach the observer to. 


---

#### <kbd>property</kbd> hostname

Get the unit's hostname. 



**Returns:**
  the unit's FQDN. 

---

#### <kbd>property</kbd> model

Shortcut for more simple access the model. 




