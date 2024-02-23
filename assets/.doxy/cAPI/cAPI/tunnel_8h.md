

# File tunnel.h



[**FileList**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**tunnel.h**](tunnel_8h.md)

[Go to the source code of this file](tunnel_8h_source.md)

_Sandwich Tunnel API._ 

* `#include <sys/types.h>`
* `#include "sandwich_c/export.h"`
* `#include "sandwich_c/io.h"`
* `#include "sandwich_c/tunnel_types.h"`















## Classes

| Type | Name |
| ---: | :--- |
| struct | [**SandwichTunnelConfigurationSerialized**](structSandwichTunnelConfigurationSerialized.md) <br>_A serialized_ `TunnelConfiguration` _message._ |
| struct | [**SandwichTunnelContextConfigurationSerialized**](structSandwichTunnelContextConfigurationSerialized.md) <br>_A serialized_ `Configuration` _message._ |
| struct | [**SandwichTunnelIO**](structSandwichTunnelIO.md) <br>_An IO specific to tunnels._  |


## Public Types

| Type | Name |
| ---: | :--- |
| typedef void() | [**SandwichTunnelIOSetStateFunction**](#typedef-sandwichtunneliosetstatefunction)  <br>_An IO callback triggered when the state of the tunnel changes._  |
| typedef [**SandwichTunnelIOSetStateFunction**](tunnel_8h.md#typedef-sandwichtunneliosetstatefunction) \* | [**SandwichTunnelIOSetStateFunctionPtr**](#typedef-sandwichtunneliosetstatefunctionptr)  <br> |




## Public Attributes

| Type | Name |
| ---: | :--- |
|  struct [**SandwichTunnelConfigurationSerialized**](structSandwichTunnelConfigurationSerialized.md) | [**SandwichTunnelConfigurationVerifierEmpty**](#variable-sandwichtunnelconfigurationverifierempty)  <br>_A tunnel configuration containing an empty Tunnel Verifier._  |
















## Public Functions

| Type | Name |
| ---: | :--- |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) struct [**SandwichTunnelIO**](structSandwichTunnelIO.md) | [**sandwich\_owned\_io\_to\_tunnel\_io**](#function-sandwich_owned_io_to_tunnel_io) (const struct [**SandwichIOOwned**](structSandwichIOOwned.md) \* owned\_io) <br>_Return the view of a tunnel IO from an owned IO._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) void | [**sandwich\_tunnel\_close**](#function-sandwich_tunnel_close) (struct SandwichTunnel \* tun) <br>_Close the tunnel._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) void | [**sandwich\_tunnel\_context\_free**](#function-sandwich_tunnel_context_free) (struct SandwichTunnelContext \* ctx) <br>_Free a Sandwich tunnel context._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) struct [**SandwichError**](structSandwichError.md) \* | [**sandwich\_tunnel\_context\_new**](#function-sandwich_tunnel_context_new) (const struct SandwichContext \* sw, struct [**SandwichTunnelContextConfigurationSerialized**](structSandwichTunnelContextConfigurationSerialized.md) configuration, struct SandwichTunnelContext \*\* ctx) <br>_Create a context from an encoded protobuf message._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) void | [**sandwich\_tunnel\_free**](#function-sandwich_tunnel_free) (struct SandwichTunnel \* tun) <br>_Free a Sandwich tunnel._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) struct [**SandwichError**](structSandwichError.md) \* | [**sandwich\_tunnel\_handshake**](#function-sandwich_tunnel_handshake) (struct SandwichTunnel \* tun, enum [**SandwichTunnelHandshakeState**](tunnel__types_8h.md#enum-sandwichtunnelhandshakestate) \* state) <br>_Perform the handshake._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) struct [**SandwichError**](structSandwichError.md) \* | [**sandwich\_tunnel\_new**](#function-sandwich_tunnel_new) (struct SandwichTunnelContext \* ctx, const struct [**SandwichTunnelIO**](structSandwichTunnelIO.md) \* io, struct [**SandwichTunnelConfigurationSerialized**](structSandwichTunnelConfigurationSerialized.md) configuration, struct SandwichTunnel \*\* tun) <br>_Create a tunnel._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) enum [**SandwichTunnelRecordError**](tunnel__types_8h.md#enum-sandwichtunnelrecorderror) | [**sandwich\_tunnel\_read**](#function-sandwich_tunnel_read) (struct SandwichTunnel \* tun, void \* dst, size\_t n, size\_t \* r) <br>_Read some bytes from the record plane of the tunnel._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) enum [**SandwichTunnelState**](tunnel__types_8h.md#enum-sandwichtunnelstate) | [**sandwich\_tunnel\_state**](#function-sandwich_tunnel_state) (const struct SandwichTunnel \* tun) <br>_Get the state of the tunnel._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) enum [**SandwichTunnelRecordError**](tunnel__types_8h.md#enum-sandwichtunnelrecorderror) | [**sandwich\_tunnel\_write**](#function-sandwich_tunnel_write) (struct SandwichTunnel \* tun, const void \* src, size\_t n, size\_t \* w) <br>_Write some bytes to the record plane of the tunnel._  |




























## Public Types Documentation




### typedef SandwichTunnelIOSetStateFunction 

_An IO callback triggered when the state of the tunnel changes._ 
```C++
typedef void() SandwichTunnelIOSetStateFunction(void *uarg, enum SandwichTunnelState tunnel_state);
```



It is guaranteed that the state of the tunnel will not change between two calls to this callback.




**Parameters:**


* `uarg` User opaque argument. 
* `tunnel_state` The new state of the tunnel. 




        



### typedef SandwichTunnelIOSetStateFunctionPtr 

```C++
typedef SandwichTunnelIOSetStateFunction* SandwichTunnelIOSetStateFunctionPtr;
```



## Public Attributes Documentation




### variable SandwichTunnelConfigurationVerifierEmpty 

```C++
struct SandwichTunnelConfigurationSerialized SandwichTunnelConfigurationVerifierEmpty;
```



## Public Functions Documentation




### function sandwich\_owned\_io\_to\_tunnel\_io 

_Return the view of a tunnel IO from an owned IO._ 
```C++
SANDWICH_API struct SandwichTunnelIO sandwich_owned_io_to_tunnel_io (
    const struct SandwichIOOwned * owned_io
) 
```





**Parameters:**


* `owned_io` Owned io.

The tunnel IO returned by this function is a view of the owned IO. It means that the user is STILL responsible for freeing the owned IO using `sandwich_io_owned_free`. Once freed, the view can no longer be used.




**Returns:**

A view of the owned IO as a tunnel IO. 





        



### function sandwich\_tunnel\_close 

_Close the tunnel._ 
```C++
SANDWICH_API void sandwich_tunnel_close (
    struct SandwichTunnel * tun
) 
```





**Parameters:**


* `tun` Tunnel to close. 




        



### function sandwich\_tunnel\_context\_free 

_Free a Sandwich tunnel context._ 
```C++
SANDWICH_API void sandwich_tunnel_context_free (
    struct SandwichTunnelContext * ctx
) 
```





**Parameters:**


* `ctx` Context to free.

NULL for `ctx` is allowed. 


        



### function sandwich\_tunnel\_context\_new 

_Create a context from an encoded protobuf message._ 
```C++
SANDWICH_API struct SandwichError * sandwich_tunnel_context_new (
    const struct SandwichContext * sw,
    struct SandwichTunnelContextConfigurationSerialized configuration,
    struct SandwichTunnelContext ** ctx
) 
```





**Parameters:**


* `sw` Top-level Sandwich context. 
* `configuration` Serialized configuration. 
* `ctx` The new Sandwich context object.



**Returns:**

NULL if no error occured, else a chain of errors. 





        



### function sandwich\_tunnel\_free 

_Free a Sandwich tunnel._ 
```C++
SANDWICH_API void sandwich_tunnel_free (
    struct SandwichTunnel * tun
) 
```



If the I/O interface is still owned by the tunnel, it will be freed too.




**Parameters:**


* `tun` Tunnel to free.

NULL for `tun` is allowed. 


        



### function sandwich\_tunnel\_handshake 

_Perform the handshake._ 
```C++
SANDWICH_API struct SandwichError * sandwich_tunnel_handshake (
    struct SandwichTunnel * tun,
    enum SandwichTunnelHandshakeState * state
) 
```





**Parameters:**


* `tun` Tunnel. 
* `state` The state of the tunnel



**Returns:**

Null if no error occured, else a chain of errors. 





        



### function sandwich\_tunnel\_new 

_Create a tunnel._ 
```C++
SANDWICH_API struct SandwichError * sandwich_tunnel_new (
    struct SandwichTunnelContext * ctx,
    const struct SandwichTunnelIO * io,
    struct SandwichTunnelConfigurationSerialized configuration,
    struct SandwichTunnel ** tun
) 
```



A tunnel is created from an IO interface. `SandwichTunnelIO` are used to create an IO interface that forwards calls to the `read`, and `write` of `SandwichTunnelIO`. The state of the tunnel is exposed to the IO interface through the [**SandwichTunnelIO**](structSandwichTunnelIO.md)-&gt;set\_state function.


Since the implementation of `sandwich_tunnel_new` makes a copy of `SandwichTunnelIO`, the caller does not need to keep `io` in memory. In other words, Sandwich does not take the ownership of `io`.




**Parameters:**


* `ctx` Sandwich context used for setting up the tunnel. 
* `io` I/O interface to use to create the I/O interface. 
* `configuration` Additional configuration the connection is subject to. A null pointer is undefined behavior. 
* `tun` The new Sandwich tunnel object.



**Returns:**

NULL if no error occured, else a chain of errors. 





        



### function sandwich\_tunnel\_read 

_Read some bytes from the record plane of the tunnel._ 
```C++
SANDWICH_API enum SandwichTunnelRecordError sandwich_tunnel_read (
    struct SandwichTunnel * tun,
    void * dst,
    size_t n,
    size_t * r
) 
```





**Parameters:**


* `tun` Tunnel.. 
* `dst` Destination buffer. 
* `n` Amount of bytes to read. 
* `r` Amount of bytes successfully read.

NULL for `r` is allowed.




**Returns:**

An error code. 





        



### function sandwich\_tunnel\_state 

_Get the state of the tunnel._ 
```C++
SANDWICH_API enum SandwichTunnelState sandwich_tunnel_state (
    const struct SandwichTunnel * tun
) 
```





**Parameters:**


* `tun` Tunnel.



**Returns:**

The state of the tunnel. 





        



### function sandwich\_tunnel\_write 

_Write some bytes to the record plane of the tunnel._ 
```C++
SANDWICH_API enum SandwichTunnelRecordError sandwich_tunnel_write (
    struct SandwichTunnel * tun,
    const void * src,
    size_t n,
    size_t * w
) 
```





**Parameters:**


* `tun` Tunnel. 
* `src` Source buffer. 
* `n` Amount of bytes to read. 
* `w` Amount of bytes successfully written.

NULL for `w` is allowed.




**Returns:**

An error code. 





        

------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/tunnel.h`

