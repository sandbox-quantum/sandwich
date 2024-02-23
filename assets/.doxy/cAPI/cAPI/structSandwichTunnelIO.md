

# Struct SandwichTunnelIO



[**ClassList**](annotated.md) **>** [**SandwichTunnelIO**](structSandwichTunnelIO.md)



_An IO specific to tunnels._ 

* `#include <tunnel.h>`





















## Public Attributes

| Type | Name |
| ---: | :--- |
|  struct [**SandwichIO**](structSandwichIO.md) | [**base**](#variable-base)  <br>_The base IO object._  |
|  [**SandwichTunnelIOSetStateFunctionPtr**](tunnel_8h.md#typedef-sandwichtunneliosetstatefunctionptr) | [**set\_state**](#variable-set_state)  <br>_The callback used to indicate when the state of the tunnel changes._  |












































## Public Attributes Documentation




### variable base 

```C++
struct SandwichIO SandwichTunnelIO::base;
```






### variable set\_state 

_The callback used to indicate when the state of the tunnel changes._ 
```C++
SandwichTunnelIOSetStateFunctionPtr SandwichTunnelIO::set_state;
```



It is guaranteed that the state of the tunnel will not change between two calls to this callback.


`NULL` is a valid value. 


        

------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/tunnel.h`

