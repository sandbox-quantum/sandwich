

# File io.h



[**FileList**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**io.h**](io_8h.md)

[Go to the source code of this file](io_8h_source.md)

_I/O abstraction for Sandwich._ 

* `#include <sys/types.h>`
* `#include "sandwich_c/export.h"`
* `#include "sandwich_c/ioerrors.h"`















## Classes

| Type | Name |
| ---: | :--- |
| struct | [**SandwichIO**](structSandwichIO.md) <br>_A generic I/O interface._  |
| struct | [**SandwichIOOwned**](structSandwichIOOwned.md) <br>_An IO owned by the Sandwich Library._  |


## Public Types

| Type | Name |
| ---: | :--- |
| typedef [**SandwichIOFlushFunction**](io_8h.md#function-sandwichioflushfunction) \* | [**SandwichIOFlushFunctionPtr**](#typedef-sandwichioflushfunctionptr)  <br> |
| typedef size\_t() | [**SandwichIOReadFunction**](#typedef-sandwichioreadfunction)  <br>_Read function for the I/O interface._  |
| typedef [**SandwichIOReadFunction**](io_8h.md#typedef-sandwichioreadfunction) \* | [**SandwichIOReadFunctionPtr**](#typedef-sandwichioreadfunctionptr)  <br> |
| typedef size\_t() | [**SandwichIOWriteFunction**](#typedef-sandwichiowritefunction)  <br>_Write function for the I/O interface._  |
| typedef [**SandwichIOWriteFunction**](io_8h.md#typedef-sandwichiowritefunction) \* | [**SandwichIOWriteFunctionPtr**](#typedef-sandwichiowritefunctionptr)  <br> |
| typedef void() | [**SandwichOwnedIOFreeFunction**](#typedef-sandwichownediofreefunction)  <br>_A destructor function for owned I/O interface._  |
| typedef [**SandwichOwnedIOFreeFunction**](io_8h.md#typedef-sandwichownediofreefunction) \* | [**SandwichOwnedIOFreeFunctionPtr**](#typedef-sandwichownediofreefunctionptr)  <br> |




















## Public Functions

| Type | Name |
| ---: | :--- |
|  enum [**SandwichIOError**](ioerrors_8h.md#enum-sandwichioerror)() | [**SandwichIOFlushFunction**](#function-sandwichioflushfunction) (void \* uarg) <br>_Flush function for the I/O interface._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) enum [**SandwichIOError**](ioerrors_8h.md#enum-sandwichioerror) | [**sandwich\_io\_client\_tcp\_new**](#function-sandwich_io_client_tcp_new) (const char \* hostname, uint16\_t port, bool async, struct [**SandwichIOOwned**](structSandwichIOOwned.md) \*\* ownedIO) <br>_Creates a TCP based IO object to be used as an IO._  |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) void | [**sandwich\_io\_owned\_free**](#function-sandwich_io_owned_free) (struct [**SandwichIOOwned**](structSandwichIOOwned.md) \* ownedIO) <br>_Frees a_ [_**SandwichIOOwned**_](structSandwichIOOwned.md) _object created by one of the sandwich\_io\_\*\_new() functions._ |
|  [**SANDWICH\_API**](export_8h.md#define-sandwich_api) enum [**SandwichIOError**](ioerrors_8h.md#enum-sandwichioerror) | [**sandwich\_io\_socket\_wrap\_new**](#function-sandwich_io_socket_wrap_new) (int fd, struct [**SandwichIOOwned**](structSandwichIOOwned.md) \*\* ownedIO) <br>_Creates an IO object that wraps a UNIX socket._  |




























## Public Types Documentation




### typedef SandwichIOFlushFunctionPtr 

```C++
typedef SandwichIOFlushFunction* SandwichIOFlushFunctionPtr;
```






### typedef SandwichIOReadFunction 

_Read function for the I/O interface._ 
```C++
typedef size_t() SandwichIOReadFunction(void *uarg, void *buf, size_t count, enum SandwichIOError *err);
```





**Parameters:**


* `uarg` User opaque argument. 
* `buf` Destination buffer. 
* `count` Amount of bytes to read. 
* `err` Error, if any.



**Returns:**

The amount of bytes successfully read, or 0. 





        



### typedef SandwichIOReadFunctionPtr 

```C++
typedef SandwichIOReadFunction* SandwichIOReadFunctionPtr;
```






### typedef SandwichIOWriteFunction 

_Write function for the I/O interface._ 
```C++
typedef size_t() SandwichIOWriteFunction(void *uarg, const void *buf, size_t count, enum SandwichIOError *err);
```





**Parameters:**


* `uarg` User opaque argument. 
* `buf` Source buffer. 
* `count` Amount of bytes to write. 
* `err` Error, if any.



**Returns:**

The amount of bytes successfully written, or 0. 





        



### typedef SandwichIOWriteFunctionPtr 

```C++
typedef SandwichIOWriteFunction* SandwichIOWriteFunctionPtr;
```






### typedef SandwichOwnedIOFreeFunction 

```C++
typedef void() SandwichOwnedIOFreeFunction(struct SandwichIO *io);
```






### typedef SandwichOwnedIOFreeFunctionPtr 

```C++
typedef SandwichOwnedIOFreeFunction* SandwichOwnedIOFreeFunctionPtr;
```



## Public Functions Documentation




### function SandwichIOFlushFunction 

_Flush function for the I/O interface._ 
```C++
enum SandwichIOError () SandwichIOFlushFunction (
    void * uarg
) 
```





**Parameters:**


* `uarg` User opaque argument.



**Returns:**

IOERROR\_OK if success, else an IO error. 





        



### function sandwich\_io\_client\_tcp\_new 

_Creates a TCP based IO object to be used as an IO._ 
```C++
SANDWICH_API enum SandwichIOError sandwich_io_client_tcp_new (
    const char * hostname,
    uint16_t port,
    bool async,
    struct SandwichIOOwned ** ownedIO
) 
```





**Parameters:**


* `hostname` the hostname of the target server. 
* `port` the port number of the target server. 
* `async` indicates whether sockets should be non-blocking or not. 
* `ownedIO` the created TCP based sandwich owned IO object.



**Returns:**

IOERROR\_OK if the operation was a success, otherwise returns the error that occurred. 





        



### function sandwich\_io\_owned\_free 

```C++
SANDWICH_API void sandwich_io_owned_free (
    struct SandwichIOOwned * ownedIO
) 
```






### function sandwich\_io\_socket\_wrap\_new 

_Creates an IO object that wraps a UNIX socket._ 
```C++
SANDWICH_API enum SandwichIOError sandwich_io_socket_wrap_new (
    int fd,
    struct SandwichIOOwned ** ownedIO
) 
```





**Parameters:**


* `fd` the file descriptor of the unix socket. 
* `ownedIO` the created UNIX socket sandwich owned IO object. The caller is responsible for freeing that object with [**sandwich\_io\_owned\_free**](io_8h.md#function-sandwich_io_owned_free).



**Returns:**

IOERROR\_OK if the operation was a success, otherwise returns the error that occurred. 





        

------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/io.h`

