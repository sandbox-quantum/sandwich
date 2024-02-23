

# Struct SandwichError



[**ClassList**](annotated.md) **>** [**SandwichError**](structSandwichError.md)



_An error code._ 

* `#include <error.h>`





















## Public Attributes

| Type | Name |
| ---: | :--- |
|  int | [**code**](#variable-code)  <br>_The error code._  |
|  struct [**SandwichError**](structSandwichError.md) \* | [**details**](#variable-details)  <br>_The encapsulated error._  |
|  [**SandwichErrorKind**](error__codes_8h.md#enum-sandwicherrorkind) | [**kind**](#variable-kind)  <br>_The error kind. See error::ErrorKind enum._  |
|  const char \* | [**msg**](#variable-msg)  <br>_An optional error string._  |












































## Public Attributes Documentation




### variable code 

```C++
int SandwichError::code;
```






### variable details 

```C++
struct SandwichError* SandwichError::details;
```






### variable kind 

```C++
SandwichErrorKind SandwichError::kind;
```






### variable msg 

```C++
const char* SandwichError::msg;
```




------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/error.h`

