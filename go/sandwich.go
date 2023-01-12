// Copyright 2022 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sandwich

/*
  #include "c/sandwich.h"
  #include <stdlib.h>
*/
import "C"

import (
	"runtime"
	"unsafe"

	pb "github.com/sandbox-quantum/sandwich/proto/sandwich"
	api "github.com/sandbox-quantum/sandwich/proto/sandwich/api/v1"
	"google.golang.org/protobuf/proto"
)

// Context wraps a `struct Context *` and exposes few methods
// for convenience.
type Context struct {
	// handle is the C handle to the `struct Context *`.
	handle *C.struct_SandwichContext
}

// NewContext fills a Sandwich context from a protobuf configuration.
func NewContext(configuration *api.Configuration) (*Context, error) {
	out, err := proto.Marshal(configuration)
	if err != nil {
		return nil, newGlobalErrorFromEnum(pb.Error_ERROR_PROTOBUF)
	}

	n := len(out)
	if n == 0 {
		return nil, newGlobalErrorFromEnum(pb.Error_ERROR_PROTOBUF)
	}

	ctx := new(Context)
	errc := C.sandwich_context_new(unsafe.Pointer(&out[0]), C.size_t(n), &ctx.handle)
	if int32(errc) != int32(pb.Error_ERROR_OK) {
		return nil, newGlobalError(int32(errc))
	}

	runtime.SetFinalizer(ctx, (*Context).free)
	return ctx, nil
}

func (ctx *Context) free() {
	C.sandwich_context_free(ctx.handle)
	ctx.handle = nil
}

// Tunnel wraps a `struct SandwichTunnel *` and exposes its methods.
type Tunnel struct {
	// handle is the C handle to the `struct SandwichTunnel *`.
	handle *C.struct_SandwichTunnel

	// ioHandle is the I/O handle to the I/O interface.
	ioHandle *cIOHandle
}

// NewTunnel creates a Sandwich tunnel from a context and an io.
func NewTunnel(ctx *Context, io IO) (*Tunnel, error) {
	tun := new(Tunnel)
	tun.ioHandle = new(cIOHandle)
	err := newcIOHandle(tun.ioHandle, io)
	if err != nil {
		return nil, err
	}

	errc := C.sandwich_tunnel_new(ctx.handle, tun.ioHandle.handle, &tun.handle)

	if int32(errc) != int32(pb.Error_ERROR_OK) {
		return nil, newGlobalError(int32(errc))
	}
	runtime.SetFinalizer(tun, (*Tunnel).free)
	return tun, nil
}

// State returns the state of the tunnel.
func (tun *Tunnel) State() pb.State {
	state := C.sandwich_tunnel_state(tun.handle)
	return pb.State(state)
}

// Error returns the last saved error of the tunnel.
// If nil is returned, it means no error occurred.
func (tun *Tunnel) Error() *GlobalError {
	err := C.sandwich_tunnel_last_error(tun.handle)
	if int32(err) == int32(pb.Error_ERROR_OK) {
		return nil
	}
	return newGlobalError(int32(err))
}

// Handshakes performs or resumes the handshake stage.
// If nil is returned, it means the handshake is done.
func (tun *Tunnel) Handshake() error {
	err := C.sandwich_tunnel_handshake(tun.handle)
	if int32(err) == int32(pb.HandshakeState_HANDSHAKESTATE_DONE) {
		return nil
	}
	return newHandshakeError(int32(err))
}

// Read implements the io.Reader interface.
func (tun *Tunnel) Read(b []byte) (int, error) {
	var read_n C.size_t = 0
	err := C.sandwich_tunnel_read(tun.handle, unsafe.Pointer(&b[0]),
		C.size_t(len(b)),
		&read_n)
	if int32(err) != int32(pb.RecordError_RECORDERROR_OK) {
		return 0, newRecordPlaneError(int32(err))
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
		return 0, newRecordPlaneError(int32(err))
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
	return tun.ioHandle.io
}

// IORelease releases the IO interface used by a tunnel.
// The returned IO object no longer belongs with the Tunnel.
func (tun *Tunnel) IORelease() *IO {
	ptr := C.sandwich_tunnel_io_release(tun.handle)
	if ptr == nil {
		return nil
	}
	return tun.ioHandle.io
}

// free frees the memory allocated for a `struct SandwichTunnel*`.
func (tun *Tunnel) free() {
	C.sandwich_tunnel_free(tun.handle)
}
