

# File error.h



[**FileList**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**error.h**](error_8h.md)

[Go to the source code of this file](error_8h_source.md)

_Error handling for the Sandwich library._ 

* `#include "sandwich_c/error_codes.h"`
* `#include "sandwich_c/export.h"`















## Classes

| Type | Name |
| ---: | :--- |
| struct | [**SandwichError**](structSandwichError.md) <br>_An error code._  |






















## Public Functions

| Type | Name |
| ---: | :--- |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) void | [**sandwich\_error\_free**](#function-sandwich_error_free) (struct [**SandwichError**](structSandwichError.md) \* chain) <br>_Free an error chain._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) void | [**sandwich\_error\_stack\_str\_free**](#function-sandwich_error_stack_str_free) (const char \* err\_str) <br>_Free a an error string (generated from sandwich\_error\_stack\_str\_new)_  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) char \* | [**sandwich\_error\_stack\_str\_new**](#function-sandwich_error_stack_str_new) (const struct [**SandwichError**](structSandwichError.md) \* chain) <br>_Create an error stack string from a_ [_**SandwichError**_](structSandwichError.md) _chain._ |




























## Public Functions Documentation




### function sandwich\_error\_free 

_Free an error chain._ 
```C++
SANDWICH_API void sandwich_error_free (
    struct SandwichError * chain
) 
```





**Parameters:**


* `chain` Error chain. 




        



### function sandwich\_error\_stack\_str\_free 

_Free a an error string (generated from sandwich\_error\_stack\_str\_new)_ 
```C++
SANDWICH_API void sandwich_error_stack_str_free (
    const char * err_str
) 
```





**Parameters:**


* `err_str` Pointer to error string to free.

NULL for err\_str is allowed. 


        



### function sandwich\_error\_stack\_str\_new 

_Create an error stack string from a_ [_**SandwichError**_](structSandwichError.md) _chain._
```C++
SANDWICH_API char * sandwich_error_stack_str_new (
    const struct SandwichError * chain
) 
```





**Parameters:**


* `chain` Error chain.



**Returns:**

A NUL terminated string describing the [**SandwichError**](structSandwichError.md) chain 





        

------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/error.h`

