

# Struct SandwichIOOwned



[**ClassList**](annotated.md) **>** [**SandwichIOOwned**](structSandwichIOOwned.md)



_An IO owned by the Sandwich Library._ [More...](#detailed-description)

* `#include <io.h>`





















## Public Attributes

| Type | Name |
| ---: | :--- |
|  [**SandwichOwnedIOFreeFunctionPtr**](io_8h.md#typedef-sandwichownediofreefunctionptr) | [**freeptr**](#variable-freeptr)  <br>_The function used to free the owned IO._  |
|  struct [**SandwichIO**](structSandwichIO.md) \* | [**io**](#variable-io)  <br>_The IO which is owned by Sandwich._  |












































# Detailed Description


[**SandwichIOOwned**](structSandwichIOOwned.md) objects own the underlying `io->uarg` object pointer, and provides a `freeptr` function that is responsible for destroying that object. [**SandwichIOOwned**](structSandwichIOOwned.md) must be freed by calling the [**sandwich\_io\_owned\_free**](io_8h.md#function-sandwich_io_owned_free) function. This is what is returned from sandwich\_io\_\*\_new functions. 


    
## Public Attributes Documentation




### variable freeptr 

```C++
SandwichOwnedIOFreeFunctionPtr SandwichIOOwned::freeptr;
```






### variable io 

```C++
struct SandwichIO* SandwichIOOwned::io;
```




------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/io.h`

