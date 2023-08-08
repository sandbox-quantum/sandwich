// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// io describes the Sandwich I/O interface.
// The I/O interface is used by the implementation to perform all i/o operation.
package sandwich

import (
	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	"io"
	"runtime"
	"unsafe"
)

/*
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include "sandwich_c/sandwich.h"


extern SandwichCIOReadFunction sandwichGoIORead;
extern SandwichCIOWriteFunction sandwichGoIOWrite;

typedef void* mutBuf;
typedef const void* constBuf;

static struct SandwichCIOSettings* allocSandwichCIOSettings(void) {
  return (struct SandwichCIOSettings*)calloc(1, sizeof(struct SandwichCIOSettings));
}

extern enum SandwichIOError sandwich_io_client_tcp_new(const char *hostname, const uint16_t port, bool async, struct SandwichCIOOwned **ownedIO);
extern void sandwich_io_owned_free(struct SandwichCIOOwned *ownedIO);

static size_t client_bridge_read(SandwichCIOReadFunctionPtr read, void *uarg, void *buf, size_t count, enum SandwichTunnelState tunnel_state, enum SandwichIOError *err) {
	return read(uarg, buf, count, tunnel_state, err);
}

static size_t client_bridge_write(SandwichCIOWriteFunctionPtr write, void *uarg, void *buf, size_t count, enum SandwichTunnelState tunnel_state, enum SandwichIOError *err) {
	return write(uarg, buf, count, tunnel_state, err);
}

*/
import "C"

// IO represents the I/O interface used by Sandwich.
type IO interface {
	// Read reads data from the connection.
	Read(b []byte, tunnel_state pb.State) (n int, err *IOError)

	// Write writes data from the connection.
	Write(b []byte, tunnel_state pb.State) (n int, err *IOError)
}

// createSettings creates a C-compatible structure from an IO interface.
func createSettings(goio *goIOWrapper) *C.struct_SandwichCIOSettings {
	set := C.allocSandwichCIOSettings()
	set.read = &C.sandwichGoIORead
	set.write = &C.sandwichGoIOWrite
	set.uarg = unsafe.Pointer(goio.io)
	return set
}

//export sandwichGoIORead
func sandwichGoIORead(ioint unsafe.Pointer, buf C.mutBuf, size C.size_t, tunnel_state C.enum_SandwichTunnelState, err *C.enum_SandwichIOError) C.size_t {
	io := *(*IO)(ioint)

	n, ioerr := io.Read(unsafe.Slice((*byte)(buf), int(size)), pb.State(tunnel_state))
	if ioerr != nil {
		*err = C.enum_SandwichIOError(((Error)(ioerr)).Code())
	} else {
		*err = C.enum_SandwichIOError(pb.IOError_IOERROR_OK)
	}
	return C.size_t(n)
}

//export sandwichGoIOWrite
func sandwichGoIOWrite(ioint unsafe.Pointer, buf C.constBuf, size C.size_t, tunnel_state C.enum_SandwichTunnelState, err *C.enum_SandwichIOError) C.size_t {
	io := *(*IO)(ioint)

	n, ioerr := io.Write(unsafe.Slice((*byte)(buf), int(size)), pb.State(tunnel_state))
	if ioerr != nil {
		*err = C.enum_SandwichIOError(((Error)(ioerr)).Code())
	} else {
		*err = C.enum_SandwichIOError(pb.IOError_IOERROR_OK)
	}
	return C.size_t(n)
}

// goIOWrapper wraps `struct SandwichCIOSettings` and `IO` together.
type goIOWrapper struct {
	settings *C.struct_SandwichCIOSettings
	io       *IO
}

// newgoIOWrapper creates a new SandwichCIOSettings from an IO interface.
func newgoIOWrapper(goio *goIOWrapper, io IO) {
	goio.io = &io
	goio.settings = createSettings(goio)
	runtime.SetFinalizer(goio, (*goIOWrapper).free)
}

// free releases the memory taken by `struct SandwichCIOSettings`.
func (goio *goIOWrapper) free() {
	C.free(unsafe.Pointer(goio.settings))
	goio.settings = nil
}

// swOwnedIOWrapper wraps `struct SandwichCIOOwned`.
type swOwnedIOWrapper struct {
	owned_io *C.struct_SandwichCIOOwned
}

// Reads implements the sandwich.IO interface for bufIO.
func (rawIO *swOwnedIOWrapper) Read(b []byte, tunnel_state pb.State) (int, *IOError) {
	settings := rawIO.owned_io.io
	count := len(b)
	buf := b
	state := uint32(tunnel_state)
	err := uint32(pb.IOError_IOERROR_UNKNOWN)
	bytes_read := C.client_bridge_read(settings.read, unsafe.Pointer(settings.uarg), unsafe.Pointer(&buf[0]), C.size_t(count), state, &err)
	pb_err := pb.IOError(err)
	if pb_err != pb.IOError_IOERROR_OK {
		return 0, NewIOErrorFromEnum(pb_err)
	}
	return int(bytes_read), nil
}

// Write implements the sandwich.IO interface for bufIO.
func (rawIO *swOwnedIOWrapper) Write(b []byte, tunnel_state pb.State) (int, *IOError) {
	settings := rawIO.owned_io.io
	count := len(b)
	buf := b
	state := uint32(tunnel_state)
	err := uint32(pb.IOError_IOERROR_UNKNOWN)
	bytes_written := C.client_bridge_write(settings.write, unsafe.Pointer(settings.uarg), unsafe.Pointer(&buf[0]), C.size_t(count), state, &err)
	pb_err := pb.IOError(err)
	if pb_err != pb.IOError_IOERROR_OK {
		return 0, NewIOErrorFromEnum(pb_err)
	}
	return int(bytes_written), nil
}

// Frees a swOwnedIOWrapper.
func (rawIO *swOwnedIOWrapper) free() {
	C.sandwich_io_owned_free(rawIO.owned_io)
}

// Creates a Sandwich owned TCP based IO Object.
func IOTCPClient(hostname string, port uint16, is_blocking bool) (*swOwnedIOWrapper, *IOError) {
	var io *C.struct_SandwichCIOOwned
	err := C.sandwich_io_client_tcp_new(C.CString(hostname), C.ushort(port), C.bool(is_blocking), &io)
	pb_err := pb.IOError(err)
	if pb_err != pb.IOError_IOERROR_OK {
		return nil, NewIOErrorFromEnum(pb_err)
	}
	client_io := new(swOwnedIOWrapper)
	client_io.owned_io = io
	runtime.SetFinalizer(client_io, (*swOwnedIOWrapper).free)
	return client_io, nil
}

// --8<-- [start:go_io_rw]
// Wraps an io.ReadWriter object
// WARNING: errors are hard to map as they are just strings. So far,
// every error returns a generic IOError_IOERROR_UNKNOWN error code.
type IORWWrapper struct {
	conn io.ReadWriter
}

func (c *IORWWrapper) Read(b []byte, tunnel_state pb.State) (int, *IOError) {
	n, err := c.conn.Read(b)
	if err != nil {
		return 0, NewIOErrorFromEnum(pb.IOError_IOERROR_UNKNOWN)
	}
	return n, nil
}

func (c *IORWWrapper) Write(b []byte, tunnel_state pb.State) (int, *IOError) {
	n, err := c.conn.Write(b)
	if err != nil {
		return 0, NewIOErrorFromEnum(pb.IOError_IOERROR_UNKNOWN)
	}
	return n, nil
}

func IOWrapRW(conn io.ReadWriter) IORWWrapper {
	return IORWWrapper{conn: conn}
}

// --8<-- [end:go_io_rw]
