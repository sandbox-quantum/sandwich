

# File ioerrors.h



[**FileList**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**ioerrors.h**](ioerrors_8h.md)

[Go to the source code of this file](ioerrors_8h_source.md)

_Sandwich I/O errors specification._ 


















## Public Types

| Type | Name |
| ---: | :--- |
| enum  | [**SandwichIOError**](#enum-sandwichioerror)  <br>_Enum IOError._  |
| typedef enum [**SandwichIOError**](ioerrors_8h.md#enum-sandwichioerror) | [**SandwichIOError**](#typedef-sandwichioerror)  <br> |
















































## Public Types Documentation




### enum SandwichIOError 

```C++
enum SandwichIOError {
    SANDWICH_IOERROR_OK = 0,
    SANDWICH_IOERROR_IN_PROGRESS = 1,
    SANDWICH_IOERROR_WOULD_BLOCK = 2,
    SANDWICH_IOERROR_REFUSED = 3,
    SANDWICH_IOERROR_CLOSED = 4,
    SANDWICH_IOERROR_INVALID = 5,
    SANDWICH_IOERROR_UNKNOWN = 6,
    SANDWICH_IOERROR_SYSTEM_ERROR = 7,
    SANDWICH_IOERROR_ADDRESS_IN_USE = 8
};
```






### typedef SandwichIOError 

```C++
typedef enum SandwichIOError SandwichIOError;
```




------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/ioerrors.h`

