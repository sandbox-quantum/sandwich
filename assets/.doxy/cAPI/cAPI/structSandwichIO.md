

# Struct SandwichIO



[**ClassList**](annotated.md) **>** [**SandwichIO**](structSandwichIO.md)



_A generic I/O interface._ 

* `#include <io.h>`





















## Public Attributes

| Type | Name |
| ---: | :--- |
|  [**SandwichIOFlushFunctionPtr**](io_8h.md#typedef-sandwichioflushfunctionptr) | [**flush**](#variable-flush)  <br>_The flush function._  |
|  [**SandwichIOReadFunctionPtr**](io_8h.md#typedef-sandwichioreadfunctionptr) | [**read**](#variable-read)  <br>_The read function._  |
|  void \* | [**uarg**](#variable-uarg)  <br>_Opaque argument to forward to read, write and flush._  |
|  [**SandwichIOWriteFunctionPtr**](io_8h.md#typedef-sandwichiowritefunctionptr) | [**write**](#variable-write)  <br>_The write function._  |












































## Public Attributes Documentation




### variable flush 

_The flush function._ 
```C++
SandwichIOFlushFunctionPtr SandwichIO::flush;
```



`NULL` is a valid value for flush. 


        



### variable read 

```C++
SandwichIOReadFunctionPtr SandwichIO::read;
```






### variable uarg 

```C++
void* SandwichIO::uarg;
```






### variable write 

```C++
SandwichIOWriteFunctionPtr SandwichIO::write;
```




------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/io.h`

