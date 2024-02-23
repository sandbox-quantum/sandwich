

# File listener.h



[**FileList**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**listener.h**](listener_8h.md)

[Go to the source code of this file](listener_8h_source.md)

_Sandwich C library, on top of the Rust implementation._ 

* `#include <sys/types.h>`
* `#include "sandwich_c/export.h"`
* `#include "sandwich_c/io.h"`





































## Public Functions

| Type | Name |
| ---: | :--- |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) enum [**SandwichIOError**](ioerrors_8h.md#enum-sandwichioerror) | [**sandwich\_listener\_accept**](#function-sandwich_listener_accept) (struct SandwichListener \* listener, struct [**SandwichIOOwned**](structSandwichIOOwned.md) \*\* ownedIO) <br>_Prompts the Listener to start accepting connections._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) void | [**sandwich\_listener\_close**](#function-sandwich_listener_close) (struct SandwichListener \* listener) <br>_Closes the listener to new connections._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) void | [**sandwich\_listener\_free**](#function-sandwich_listener_free) (struct SandwichListener \* listener) <br>_Frees the given listener._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) enum [**SandwichIOError**](ioerrors_8h.md#enum-sandwichioerror) | [**sandwich\_listener\_listen**](#function-sandwich_listener_listen) (struct SandwichListener \* listener) <br>_Causes the Listener to start listening for connections._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) struct [**SandwichError**](structSandwichError.md) \* | [**sandwich\_listener\_new**](#function-sandwich_listener_new) (const void \* src, size\_t n, struct SandwichListener \*\* out) <br>_Creates a a new Listener object._  |




























## Public Functions Documentation




### function sandwich\_listener\_accept 

_Prompts the Listener to start accepting connections._ 
```C++
SANDWICH_API enum SandwichIOError sandwich_listener_accept (
    struct SandwichListener * listener,
    struct SandwichIOOwned ** ownedIO
) 
```





**Parameters:**


* `listener` the listener which should start accepting connections. 
* `ownedIO` the newly created OwnedIO struct containing the IO object to use with a tunnel. Null if an error occurs.



**Returns:**

IOERROR\_OK if the operation was a success, otherwise returns the error that occurred. 





        



### function sandwich\_listener\_close 

_Closes the listener to new connections._ 
```C++
SANDWICH_API void sandwich_listener_close (
    struct SandwichListener * listener
) 
```





**Parameters:**


* `listener` the listener which should close. 




        



### function sandwich\_listener\_free 

_Frees the given listener._ 
```C++
SANDWICH_API void sandwich_listener_free (
    struct SandwichListener * listener
) 
```





**Parameters:**


* `listener` the listener which should start accepting connections. 




        



### function sandwich\_listener\_listen 

_Causes the Listener to start listening for connections._ 
```C++
SANDWICH_API enum SandwichIOError sandwich_listener_listen (
    struct SandwichListener * listener
) 
```





**Parameters:**


* `listener` The listener object that should start listening for new connections.



**Returns:**

IOERROR\_OK if the operation was a success, otherwise returns the error that occurred. 





        



### function sandwich\_listener\_new 

_Creates a a new Listener object._ 
```C++
SANDWICH_API struct SandwichError * sandwich_listener_new (
    const void * src,
    size_t n,
    struct SandwichListener ** out
) 
```





**Parameters:**


* `src` a serialized `ListenerConfiguration` protobuf message. 
* `n` the length of src. 
* `out` points to the newly created listener.



**Returns:**

Error, if any. 





        

------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/listener.h`

