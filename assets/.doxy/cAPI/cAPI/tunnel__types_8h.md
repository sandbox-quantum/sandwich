

# File tunnel\_types.h



[**FileList**](files.md) **>** [**docs**](dir_49e56c817e5e54854c35e136979f97ca.md) **>** [**sandwich\_c**](dir_f6ef5a90171f1138cc160f006fc74f9c.md) **>** [**tunnel\_types.h**](tunnel__types_8h.md)

[Go to the source code of this file](tunnel__types_8h_source.md)

_Sandwich tunnel types and states specification._ 


















## Public Types

| Type | Name |
| ---: | :--- |
| enum  | [**SandwichTunnelHandshakeState**](#enum-sandwichtunnelhandshakestate)  <br>_Enum HandshakeState._  |
| typedef enum [**SandwichTunnelHandshakeState**](tunnel__types_8h.md#enum-sandwichtunnelhandshakestate) | [**SandwichTunnelHandshakeState**](#typedef-sandwichtunnelhandshakestate)  <br> |
| enum  | [**SandwichTunnelRecordError**](#enum-sandwichtunnelrecorderror)  <br>_Enum RecordError._  |
| typedef enum [**SandwichTunnelRecordError**](tunnel__types_8h.md#enum-sandwichtunnelrecorderror) | [**SandwichTunnelRecordError**](#typedef-sandwichtunnelrecorderror)  <br> |
| enum  | [**SandwichTunnelState**](#enum-sandwichtunnelstate)  <br>_Enum State._  |
| typedef enum [**SandwichTunnelState**](tunnel__types_8h.md#enum-sandwichtunnelstate) | [**SandwichTunnelState**](#typedef-sandwichtunnelstate)  <br> |
















































## Public Types Documentation




### enum SandwichTunnelHandshakeState 

```C++
enum SandwichTunnelHandshakeState {
    SANDWICH_TUNNEL_HANDSHAKESTATE_IN_PROGRESS = 0,
    SANDWICH_TUNNEL_HANDSHAKESTATE_DONE = 1,
    SANDWICH_TUNNEL_HANDSHAKESTATE_WANT_READ = 2,
    SANDWICH_TUNNEL_HANDSHAKESTATE_WANT_WRITE = 3,
    SANDWICH_TUNNEL_HANDSHAKESTATE_ERROR = 4
};
```






### typedef SandwichTunnelHandshakeState 

```C++
typedef enum SandwichTunnelHandshakeState SandwichTunnelHandshakeState;
```






### enum SandwichTunnelRecordError 

```C++
enum SandwichTunnelRecordError {
    SANDWICH_TUNNEL_RECORDERROR_OK = 0,
    SANDWICH_TUNNEL_RECORDERROR_WANT_READ = 1,
    SANDWICH_TUNNEL_RECORDERROR_WANT_WRITE = 2,
    SANDWICH_TUNNEL_RECORDERROR_BEING_SHUTDOWN = 3,
    SANDWICH_TUNNEL_RECORDERROR_CLOSED = 4,
    SANDWICH_TUNNEL_RECORDERROR_TOO_BIG = 5,
    SANDWICH_TUNNEL_RECORDERROR_UNKNOWN = 6
};
```






### typedef SandwichTunnelRecordError 

```C++
typedef enum SandwichTunnelRecordError SandwichTunnelRecordError;
```






### enum SandwichTunnelState 

```C++
enum SandwichTunnelState {
    SANDWICH_TUNNEL_STATE_NOT_CONNECTED = 0,
    SANDWICH_TUNNEL_STATE_CONNECTION_IN_PROGRESS = 1,
    SANDWICH_TUNNEL_STATE_HANDSHAKE_IN_PROGRESS = 2,
    SANDWICH_TUNNEL_STATE_HANDSHAKE_DONE = 3,
    SANDWICH_TUNNEL_STATE_BEING_SHUTDOWN = 4,
    SANDWICH_TUNNEL_STATE_DISCONNECTED = 5,
    SANDWICH_TUNNEL_STATE_ERROR = 6
};
```






### typedef SandwichTunnelState 

```C++
typedef enum SandwichTunnelState SandwichTunnelState;
```




------------------------------
The documentation for this class was generated from the following file `docs/sandwich_c/tunnel_types.h`

