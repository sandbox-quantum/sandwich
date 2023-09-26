// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package sandwich

/*
  #include <stdbool.h>
  #include <stdint.h>
  #include "sandwich_c/sandwich.h"
  #include <stdlib.h>
*/
import "C"

import (
	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	"runtime"
	"unsafe"

	api "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"

	"google.golang.org/protobuf/proto"
)

// TunnelContext wraps a `struct Context *` and exposes few methods
// for convenience.
type TunnelContext struct {
	// handle is the C handle to the `struct Context *`.
	handle *C.struct_SandwichTunnelContext
}

// NewTunnelContext fills a Sandwich context from a protobuf configuration.
func NewTunnelContext(sw *Sandwich, configuration *api.Configuration) (*TunnelContext, error) {
	out, err := proto.Marshal(configuration)
	if err != nil {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED, "")
	}

	n := len(out)
	if n == 0 {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_EMPTY, "")
	}

	conf := C.struct_SandwichTunnelContextConfigurationSerialized{
		src: unsafe.Pointer(&out[0]),
		n:   C.size_t(n),
	}

	ctx := new(TunnelContext)
	errc := C.sandwich_tunnel_context_new(sw.handle, conf, &ctx.handle)
	if errc != nil {
		err := createError(errc)
		C.sandwich_error_free(errc)
		return nil, err
	}

	runtime.SetFinalizer(ctx, (*TunnelContext).free)
	return ctx, nil
}

func (ctx *TunnelContext) free() {
	C.sandwich_tunnel_context_free(ctx.handle)
	ctx.handle = nil
}

// Tunnel wraps a `struct SandwichTunnel *` and exposes its methods.
type Tunnel struct {
	// handle is the C handle to the `struct SandwichTunnel *`.
	handle *C.struct_SandwichTunnel

	// goIO is the I/O interface.
	goIO *goIOWrapper
}

// NewTunnel creates a Sandwich tunnel from a context, an io and a configuration.
func NewTunnel(ctx *TunnelContext, io IO, configuration *api.TunnelConfiguration) (*Tunnel, error) {
	out, err := proto.Marshal(configuration)
	if err != nil {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED, "")
	}

	n := len(out)
	if n == 0 {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_EMPTY, "")
	}

	tun := new(Tunnel)
	tun.goIO = new(goIOWrapper)
	newgoIOWrapper(tun.goIO, io)

	conf := C.struct_SandwichTunnelConfigurationSerialized{
		src: unsafe.Pointer(&out[0]),
		n:   C.size_t(n),
	}

	errc := C.sandwich_tunnel_new(ctx.handle, tun.goIO.settings, conf, &tun.handle)
	if errc != nil {
		err := createError(errc)
		C.sandwich_error_free(errc)
		return nil, err
	}

	runtime.SetFinalizer(tun, (*Tunnel).free)
	return tun, nil
}

// State returns the state of the tunnel.
func (tun *Tunnel) State() pb.State {
	state := C.sandwich_tunnel_state(tun.handle)
	return pb.State(state)
}

// Handshakes performs or resumes the handshake stage.
// If nil is returned, it means the handshake is done.
func (tun *Tunnel) Handshake() error {
	var state uint32 = 0
	errc := C.sandwich_tunnel_handshake(tun.handle, &state)
	if errc != nil {
		err := createError(errc)
		C.sandwich_error_free(errc)
		return err
	}
	if int32(state) == int32(pb.HandshakeState_HANDSHAKESTATE_DONE) {
		return nil
	}
	return newHandshakeStateError(int32(state), "")
}

// Read implements the io.Reader interface.
func (tun *Tunnel) Read(b []byte) (int, error) {
	var read_n C.size_t = 0
	err := C.sandwich_tunnel_read(tun.handle, unsafe.Pointer(&b[0]),
		C.size_t(len(b)),
		&read_n)
	if int32(err) != int32(pb.RecordError_RECORDERROR_OK) {
		return 0, newRecordPlaneError(int32(err), "")
	}
	return int(read_n), nil
}

// Write implements the io.Reader interface.
func (tun *Tunnel) Write(b []byte) (int, error) {
	var write_n C.size_t = 0
	err := C.sandwich_tunnel_write(tun.handle, unsafe.Pointer(&b[0]),
		C.size_t(len(b)),
		&write_n)
	if int32(err) != int32(pb.RecordError_RECORDERROR_OK) {
		return 0, newRecordPlaneError(int32(err), "")
	}
	return int(write_n), nil
}

// Close closes the tunnel.
func (tun *Tunnel) Close() error {
	C.sandwich_tunnel_close(tun.handle)
	return nil
}

// IO returns the IO interface used by a tunnel.
// The interface is borrowed to the user. Its ownership remains to the Tunnel.
func (tun *Tunnel) IO() *IO {
	return tun.goIO.io
}

// free frees the memory allocated for a `struct SandwichTunnel*`.
func (tun *Tunnel) free() {
	C.sandwich_tunnel_free(tun.handle)
}
