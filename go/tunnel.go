// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package sandwich

/*
  #include <stdbool.h>
  #include <stdint.h>
  #include "sandwich_c/io.h"
  #include "sandwich_c/sandwich.h"
  #include "sandwich_c/tunnel.h"
  #include <stdlib.h>

extern SandwichIOReadFunction sandwichGoTunnelIORead;
extern SandwichIOWriteFunction sandwichGoTunnelIOWrite;
extern SandwichIOFlushFunction sandwichGoTunnelIOFlush;
extern SandwichTunnelIOSetStateFunction sandwichGoTunnelSetState;

typedef void* mutBuf;
typedef const void* constBuf;

static struct SandwichTunnelIO* allocSandwichTunnelIO(void) {
  return (struct SandwichTunnelIO*)calloc(1, sizeof(struct SandwichTunnelIO));
}

*/
import "C"

import (
	"context"

	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	"runtime"
	"unsafe"

	api "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

// TunnelIO represents the I/O interface used by tunnels in Sandwich.
type TunnelIO interface {
	// TunnelIO is an IO.
	IO

	// SetState sets the state of the tunnel.
	//
	// It is guaranteed that the state of the tunnel will not change between
	// two calls to SetState.
	SetState(tunnel_state pb.State)
}

// createCTunnelIO creates a C `SandwichTunnelIO` structure.
func createCTunnelIO() *C.struct_SandwichTunnelIO {
	tunnelIo := C.allocSandwichTunnelIO()
	tunnelIo.base.read = &C.sandwichGoTunnelIORead
	tunnelIo.base.write = &C.sandwichGoTunnelIOWrite
	tunnelIo.base.flush = &C.sandwichGoTunnelIOFlush
	tunnelIo.set_state = &C.sandwichGoTunnelSetState
	return tunnelIo
}

//export sandwichGoTunnelIORead
func sandwichGoTunnelIORead(ioint unsafe.Pointer, buf C.mutBuf, size C.size_t, err *C.enum_SandwichIOError) C.size_t {
	tunnelIo := *(*TunnelIO)(ioint)

	n, ioerr := tunnelIo.Read(unsafe.Slice((*byte)(buf), int(size)))
	if ioerr != nil {
		*err = C.enum_SandwichIOError(((Error)(ioerr)).Code())
	} else {
		*err = C.enum_SandwichIOError(pb.IOError_IOERROR_OK)
	}
	return C.size_t(n)
}

//export sandwichGoTunnelIOWrite
func sandwichGoTunnelIOWrite(ioint unsafe.Pointer, buf C.constBuf, size C.size_t, err *C.enum_SandwichIOError) C.size_t {
	tunnelIo := *(*TunnelIO)(ioint)

	n, ioerr := tunnelIo.Write(unsafe.Slice((*byte)(buf), int(size)))
	if ioerr != nil {
		*err = C.enum_SandwichIOError(((Error)(ioerr)).Code())
	} else {
		*err = C.enum_SandwichIOError(pb.IOError_IOERROR_OK)
	}
	return C.size_t(n)
}

//export sandwichGoTunnelIOFlush
func sandwichGoTunnelIOFlush(ioint unsafe.Pointer) C.enum_SandwichIOError {
	tunnelIo := *(*TunnelIO)(ioint)

	ioerr := tunnelIo.Flush()

	if ioerr != nil {
		return C.enum_SandwichIOError(((Error)(ioerr)).Code())
	} else {
		return C.enum_SandwichIOError(0)
	}
}

//export sandwichGoTunnelSetState
func sandwichGoTunnelSetState(ioint unsafe.Pointer, tunnelState C.enum_SandwichTunnelState) {
	tunnelIo := *(*TunnelIO)(ioint)

	tunnelIo.SetState(pb.State(tunnelState))
}

// goTunnelIOWrapper wraps `struct SandwichTunnelIO` and `IO` together.
type goTunnelIOWrapper struct {
	cio      *C.struct_SandwichTunnelIO
	tunnelIo *TunnelIO
}

// newgoTunnelIOWrapper combines a TunnelIO and a C struct SandwichTunnelIO
// to create a goTunnelIOWrapper.
func newgoTunnelIOWrapper(tunnelIoWrapper *goTunnelIOWrapper, tunnelIo TunnelIO) {
	tunnelIoWrapper.tunnelIo = &tunnelIo
	tunnelIoWrapper.cio = createCTunnelIO()
	tunnelIoWrapper.cio.base.uarg = unsafe.Pointer(tunnelIoWrapper.tunnelIo)
	runtime.SetFinalizer(tunnelIoWrapper, (*goTunnelIOWrapper).free)
}

// free releases the memory taken by `struct SandwichTunnelIO`.
func (tunnelIoWrapper *goTunnelIOWrapper) free() {
	C.free(unsafe.Pointer(tunnelIoWrapper.cio))
	tunnelIoWrapper.cio = nil
}

// SetState implements TunnelIO for swOwnedIOWrapper.
func (ownedIo *swOwnedIOWrapper) SetState(tunnelState pb.State) {}

// SetState implements TunnelIO for IORWWrapper.
func (c *IORWWrapper) SetState(tunnelState pb.State) {}

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

	// ioWrapper is the wrapped tunnel I/O interface.
	ioWrapper *goTunnelIOWrapper

	// Tracer
	tracer *SandwichTracer
}

// NewTunnel creates a Sandwich tunnel from a context, an io and a configuration.
func NewTunnel(ctx *TunnelContext, tunnelIo TunnelIO, configuration *api.TunnelConfiguration) (*Tunnel, error) {
	out, err := proto.Marshal(configuration)
	if err != nil {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED, "")
	}

	n := len(out)
	if n == 0 {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_EMPTY, "")
	}

	tun := new(Tunnel)
	tun.ioWrapper = new(goTunnelIOWrapper)
	newgoTunnelIOWrapper(tun.ioWrapper, tunnelIo)

	conf := C.struct_SandwichTunnelConfigurationSerialized{
		src: unsafe.Pointer(&out[0]),
		n:   C.size_t(n),
	}

	errc := C.sandwich_tunnel_new(ctx.handle, tun.ioWrapper.cio, conf, &tun.handle)
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
	tun._flush_tracer()
	C.sandwich_tunnel_close(tun.handle)
	return nil
}

func (tun *Tunnel) Set_tracer(ctx context.Context, tracer trace.Tracer) {
	sandwich_tracer := NewSandwichTracer(ctx, tracer)
	tun.tracer = &sandwich_tracer
	C.sandwich_tunnel_add_tracer(tun.handle, C.CString(sandwich_tracer.context_string), C.int(sandwich_tracer.write_buf_fd))
	return
}

func (tun *Tunnel) _flush_tracer() {
	if tun.tracer != nil {
		tun.tracer.export_span_buffer()
	}
	return
}

// IO returns the IO interface used by a tunnel.
// The interface is borrowed to the user. Its ownership remains to the Tunnel.
func (tun *Tunnel) IO() *TunnelIO {
	return tun.ioWrapper.tunnelIo
}

// free frees the memory allocated for a `struct SandwichTunnel*`.
func (tun *Tunnel) free() {
	C.sandwich_tunnel_free(tun.handle)
}
