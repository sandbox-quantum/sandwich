# Socket

## Description

`Socket` is a helper class that wrap around `socket.socket` class, mainly to provide additional [`Errors`](./error.md), Exceptions in [`Sandwich`](./sandwich.md)

## Usage

```python
import sandwich.io as SandwichIO

def create_io() -> SandwichIO.IO:
    s = socket.socket(family=socket.AF_UNIX, type=SOCK_STREAM)
    return SandwichIO.Socket(s)

if __name__ == "__main__":
    sandwich = Sandwich()

    client_ctx = create_client_context(sandwich)
    client_io = create_io()

    server_ctx = create_server_context(sandwich)
    server_io = create_io()

    client = Tunnel(client_ctx, client_io)
    server = Tunnel(client_ctx, client_io)

    ...
```
