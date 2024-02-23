

# File tracer.h



[**FileList**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**tracer.h**](tracer_8h.md)

[Go to the source code of this file](tracer_8h_source.md)

_Sandwich Tracer API._ 

* `#include <sys/types.h>`
* `#include "sandwich_c/export.h"`
* `#include "sandwich_c/tunnel.h"`





































## Public Functions

| Type | Name |
| ---: | :--- |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) void | [**sandwich\_tunnel\_add\_tracer**](#function-sandwich_tunnel_add_tracer) (struct SandwichTunnel \* tun, const char \* context\_cstr, int fd) <br>_Adds a tracer object to a tunnel, allows for context propagation._  |




























## Public Functions Documentation




### function sandwich\_tunnel\_add\_tracer 

_Adds a tracer object to a tunnel, allows for context propagation._ 
```C++
SANDWICH_API void sandwich_tunnel_add_tracer (
    struct SandwichTunnel * tun,
    const char * context_cstr,
    int fd
) 
```





**Parameters:**


* `tun` Tunnel to associate tracer with. 
* `context_cstr` A string representing the context from OpenTelemetry. 
* `fd` File Descriptor where the tracer will write to. 




        

------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/tracer.h`

