// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package c

/*
  #include <stdbool.h>
  #include <stdint.h>
  #include "sandwich_c/lib.h"
  #include "sandwich_c/tracer.h"
  #include "sandwich_c/tunnel.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// TunnelContext wraps a C pointer to a Sandwich tunnel context.
type TunnelContext struct {
	// handle is the C handle to the Sandwich tunnel context.
	handle *C.struct_SandwichTunnelContext
}

// free releases the memory occupied by a Sandwich tunnel context.
func (ctx *TunnelContext) free() {
	C.sandwich_tunnel_context_free(ctx.handle)
	ctx.handle = nil
}

// NewTunnelContext creates a new TunnelContext.
func NewTunnelContext(lib *Lib, serialized_configuration []byte) (*TunnelContext, *Error) {
	configuration := C.struct_SandwichTunnelContextConfigurationSerialized{
		src: unsafe.Pointer(&serialized_configuration[0]),
		n:   C.size_t(len(serialized_configuration)),
	}

	ctx := new(TunnelContext)
	err := C.sandwich_tunnel_context_new(lib.handle, configuration, &ctx.handle)
	if err != nil {
		return nil, NewErrorFromPointer(err)
	}

	runtime.SetFinalizer(ctx, (*TunnelContext).free)
	return ctx, nil
}

// Tunnel wraps a C pointer to a Sandwich tunnel.
type Tunnel struct {
	// ctx is the context from which the tunnel has been made.
	ctx *TunnelContext

	// handle is the C handle to the Sandwich tunnel.
	handle *C.struct_SandwichTunnel

	// tunnelIO is the Sandwich tunnel IO being used by the tunnel.
	tunnelIO *tunnelIOWrapper
}

// free releases the memory occupied by a Sandwich tunnel.
func (tunnel *Tunnel) free() {
	C.sandwich_tunnel_free(tunnel.handle)
	tunnel.handle = nil
	tunnel.ctx = nil
	tunnel.tunnelIO = nil
}

// NewTunnel creates a new tunnel using a Sandwich tunnel context.
func (tunnelContext *TunnelContext) NewTunnel(serialized_configuration []byte, tunnelIO TunnelIO) (*Tunnel, *Error) {
	tunnel := &Tunnel{
		ctx:      tunnelContext,
		handle:   nil,
		tunnelIO: newTunnelIOWrapper(tunnelIO),
	}
	configuration := C.struct_SandwichTunnelConfigurationSerialized{
		src: unsafe.Pointer(&serialized_configuration[0]),
		n:   C.size_t(len(serialized_configuration)),
	}

	err := C.sandwich_tunnel_new(tunnelContext.handle, tunnel.tunnelIO.handle, configuration, &tunnel.handle)
	if err != nil {
		return nil, NewErrorFromPointer(err)
	}

	runtime.SetFinalizer(tunnel, (*Tunnel).free)
	return tunnel, nil
}

// Read reads data from the tunnel.
func (tunnel *Tunnel) Read(buffer []byte) (int, uint32) {
	var n C.size_t = 0
	err := C.sandwich_tunnel_read(tunnel.handle, unsafe.Pointer(&buffer[0]), C.size_t(len(buffer)), &n)
	return int(n), err
}

// Write write data to the tunnel.
func (tunnel *Tunnel) Write(buffer []byte) (int, uint32) {
	var n C.size_t = 0
	err := C.sandwich_tunnel_write(tunnel.handle, unsafe.Pointer(&buffer[0]), C.size_t(len(buffer)), &n)
	return int(n), err
}

// GetState returns the state of the tunnel.
func (tunnel *Tunnel) GetState() uint32 {
	return uint32(C.sandwich_tunnel_state(tunnel.handle))
}

// Handshake performs or resumes the handshake stage.
func (tunnel *Tunnel) Handshake() (uint32, *Error) {
	var state uint32 = 0
	err := C.sandwich_tunnel_handshake(tunnel.handle, &state)
	if err != nil {
		return state, NewErrorFromPointer(err)
	}
	return state, nil
}

// AttachTracer attaches a tracer to the tunnel.
func (tunnel *Tunnel) AttachTracer(contextString string, fd int32) {
	C.sandwich_tunnel_add_tracer(tunnel.handle, C.CString(contextString), C.int(fd))
}
