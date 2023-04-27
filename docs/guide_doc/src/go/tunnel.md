# Tunnel

## Description

`Tunnel` class wraps a `struct SandwichTunnel` and exposes methods for using the `Sandwich Backend`, such as:
-  `State`
-  `Handshake`
-  `Read`
-  `Write`
-  `Close`

Inputs:

- [`Context`](context.md): Context handle for creating the tunnel
- [`IO`](io.md): I/O interface to use


## Usage

```go

// Read config
err := proto.Unmarshal(server_proto, server_config)
if err != nil {
    t.Errorf("Failed to read Server protobuf file: %v", err)
}

err = proto.Unmarshal(client_proto, client_config)
if err != nil {
    t.Errorf("Failed to read Client protobuf file: %v", err)
}

// Create Context
serverContext, err := createContext(server_config)
if err != nil {
    t.Errorf("Failed to read Server context: %v", err)
}

clientContext, err := createContext(client_config)
if err != nil {
    t.Errorf("Failed to read Client context: %v", err)
}

// Create IOs

client, server = createIOs()

// Create Tunnel

serverTunnel, err := sandwich.NewTunnel(serverContext, io)
if err != nil {
    t.Errorf("Failed to read Client tunnel: %v", err)
}

clientTunnel, err := sandwich.NewTunnel(clientContext, io)
if err != nil {
    t.Errorf("Failed to read Client tunnel: %v", err)
}


// Handshake
err = clientTunnel.Handshake()
if err != nil {
    t.Errorf("Expected no error, got %v", err)
}
err = serverTunnel.Handshake()
if err != nil {
    t.Errorf("Expected no error, got %v", err)
}

pingMsg = [...]byte{'P', 'I', 'N', 'G'}

n, err := clientTunnel.Write(pingMsg)
if err != nil {
    t.Errorf("Expected no error, got %v", err)
}
if n != len(pingMsg) {
    t.Errorf("Expected %v bytes sent, got %v", len(pingMsg), n)
}

var buf [len(pingMsg)]byte

n, err = serverTunnel.Read(buf[:])
if err != nil {
    t.Errorf("Expected no error, got %v", err)
}
if n != len(pingMsg) {
    t.Errorf("Expected %v bytes read, got %v", len(pingMsg), n)
}
if buf != pingMsg {
    t.Errorf("Expected %v, got %v", pingMsg, buf)
}

client.Close()
server.Close()

```
