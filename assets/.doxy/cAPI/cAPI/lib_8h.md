

# File lib.h



[**FileList**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**lib.h**](lib_8h.md)

[Go to the source code of this file](lib_8h_source.md)

_Top-level context for the Sandwich library._ 

* `#include "sandwich_c/export.h"`





































## Public Functions

| Type | Name |
| ---: | :--- |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) void | [**sandwich\_lib\_context\_free**](#function-sandwich_lib_context_free) (struct SandwichContext \* sw) <br>_Free a top-level Sandwich context._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) struct SandwichContext \* | [**sandwich\_lib\_context\_new**](#function-sandwich_lib_context_new) (void) <br>_Create a top-level Sandwich context._  |




























## Public Functions Documentation




### function sandwich\_lib\_context\_free 

_Free a top-level Sandwich context._ 
```C++
SANDWICH_API void sandwich_lib_context_free (
    struct SandwichContext * sw
) 
```





**Parameters:**


* `sw` Top-level Sandwich context to free.

NULL for `sw` is allowed. 


        



### function sandwich\_lib\_context\_new 

_Create a top-level Sandwich context._ 
```C++
SANDWICH_API struct SandwichContext * sandwich_lib_context_new (
    void
) 
```





**Returns:**

A new top-level Sandwich context. 





        

------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/lib.h`

