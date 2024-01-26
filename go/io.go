// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// io describes the Sandwich I/O interface.
// The I/O interface is used by the implementation to perform all i/o operation.
package sandwich

import (
	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	api "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"
	"io"
	"runtime"
	"unsafe"

	"google.golang.org/protobuf/proto"
)

/*
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include "sandwich_c/sandwich.h"
#include "sandwich_c/io.h"
#include "sandwich_c/listener.h"


extern SandwichIOReadFunction sandwichGoIORead;
extern SandwichIOWriteFunction sandwichGoIOWrite;
extern SandwichIOFlushFunction sandwichGoIOFlush;

typedef void* mutBuf;
typedef const void* constBuf;

static struct SandwichIO* allocSandwichIO(void) {
  return (struct SandwichIO*)calloc(1, sizeof(struct SandwichIO));
}

static size_t client_bridge_read(SandwichIOReadFunctionPtr read, void *uarg, void *buf, size_t count, enum SandwichIOError *err) {
	return read(uarg, buf, count, err);
}

static size_t client_bridge_write(SandwichIOWriteFunctionPtr write, void *uarg, void *buf, size_t count, enum SandwichIOError *err) {
	return write(uarg, buf, count, err);
}

static enum SandwichIOError client_bridge_flush(SandwichIOFlushFunctionPtr flush, void *uarg) {
  enum SandwichIOError err = SANDWICH_IOERROR_OK;
  if (flush != NULL) {
    err = flush(uarg);
  }
  return err;
}

*/
import "C"

// IO represents the I/O interface used by Sandwich.
type IO interface {
	// Read reads data from the connection.
	Read(b []byte) (n int, err *IOError)

	// Write writes data from the connection.
	Write(b []byte) (n int, err *IOError)

	// Flush flushes data from the connection.
	Flush() *IOError
}

// createSettings creates a C-compatible structure from an IO interface.
func createSettings(goio *goIOWrapper) *C.struct_SandwichIO {
	set := C.allocSandwichIO()
	set.read = &C.sandwichGoIORead
	set.write = &C.sandwichGoIOWrite
	set.flush = &C.sandwichGoIOFlush
	set.uarg = unsafe.Pointer(goio.io)
	return set
}

//export sandwichGoIORead
func sandwichGoIORead(ioint unsafe.Pointer, buf C.mutBuf, size C.size_t, err *C.enum_SandwichIOError) C.size_t {
	io := *(*IO)(ioint)

	n, ioerr := io.Read(unsafe.Slice((*byte)(buf), int(size)))
	if ioerr != nil {
		*err = C.enum_SandwichIOError(((Error)(ioerr)).Code())
	} else {
		*err = C.enum_SandwichIOError(pb.IOError_IOERROR_OK)
	}
	return C.size_t(n)
}

//export sandwichGoIOWrite
func sandwichGoIOWrite(ioint unsafe.Pointer, buf C.constBuf, size C.size_t, err *C.enum_SandwichIOError) C.size_t {
	io := *(*IO)(ioint)

	n, ioerr := io.Write(unsafe.Slice((*byte)(buf), int(size)))
	if ioerr != nil {
		*err = C.enum_SandwichIOError(((Error)(ioerr)).Code())
	} else {
		*err = C.enum_SandwichIOError(pb.IOError_IOERROR_OK)
	}
	return C.size_t(n)
}

//export sandwichGoIOFlush
func sandwichGoIOFlush(ioint unsafe.Pointer) C.enum_SandwichIOError {
	io := *(*IO)(ioint)

	ioerr := io.Flush()

	if ioerr != nil {
		return C.enum_SandwichIOError(((Error)(ioerr)).Code())
	} else {
		return C.enum_SandwichIOError(0)
	}
}

// goIOWrapper wraps `struct SandwichIO` and `IO` together.
type goIOWrapper struct {
	settings *C.struct_SandwichIO
	io       *IO
}

// newgoIOWrapper creates a new SandwichIO from an IO interface.
func newgoIOWrapper(goio *goIOWrapper, io IO) {
	goio.io = &io
	goio.settings = createSettings(goio)
	runtime.SetFinalizer(goio, (*goIOWrapper).free)
}

// free releases the memory taken by `struct SandwichIO`.
func (goio *goIOWrapper) free() {
	C.free(unsafe.Pointer(goio.settings))
	goio.settings = nil
}

// swOwnedIOWrapper wraps `struct SandwichIOOwned`.
type swOwnedIOWrapper struct {
	handle *C.struct_SandwichIOOwned
}

// Reads implements the sandwich.IO interface for bufIO.
func (rawIO *swOwnedIOWrapper) Read(b []byte) (int, *IOError) {
	settings := rawIO.handle.io
	count := len(b)
	buf := b
	err := uint32(pb.IOError_IOERROR_UNKNOWN)
	bytes_read := C.client_bridge_read(settings.read, unsafe.Pointer(settings.uarg), unsafe.Pointer(&buf[0]), C.size_t(count), &err)
	pb_err := pb.IOError(err)
	if pb_err != pb.IOError_IOERROR_OK {
		return 0, NewIOErrorFromEnum(pb_err)
	}
	return int(bytes_read), nil
}

// Write implements the sandwich.IO interface for bufIO.
func (rawIO *swOwnedIOWrapper) Write(b []byte) (int, *IOError) {
	settings := rawIO.handle.io
	count := len(b)
	buf := b
	err := uint32(pb.IOError_IOERROR_UNKNOWN)
	bytes_written := C.client_bridge_write(settings.write, unsafe.Pointer(settings.uarg), unsafe.Pointer(&buf[0]), C.size_t(count), &err)
	pb_err := pb.IOError(err)
	if pb_err != pb.IOError_IOERROR_OK {
		return 0, NewIOErrorFromEnum(pb_err)
	}
	return int(bytes_written), nil
}

// Write implements the sandwich.IO interface for bufIO.
func (rawIO *swOwnedIOWrapper) Flush() *IOError {
	settings := rawIO.handle.io
	err := C.client_bridge_flush(settings.flush, unsafe.Pointer(settings.uarg))
	pb_err := pb.IOError(err)
	if pb_err != pb.IOError_IOERROR_OK {
		return NewIOErrorFromEnum(pb_err)
	}
	return nil
}

// Frees a swOwnedIOWrapper.
func (rawIO *swOwnedIOWrapper) free() {
	C.sandwich_io_owned_free(rawIO.handle)
}

// --8<-- [start:go_io_rw]
// Wraps an io.ReadWriter object
// WARNING: errors are hard to map as they are just strings. So far,
// every error returns a generic IOError_IOERROR_UNKNOWN error code.
type IORWWrapper struct {
	conn io.ReadWriter
}

func (c *IORWWrapper) Read(b []byte) (int, *IOError) {
	n, err := c.conn.Read(b)
	if err != nil {
		return 0, NewIOErrorFromEnum(pb.IOError_IOERROR_UNKNOWN)
	}
	return n, nil
}

func (c *IORWWrapper) Write(b []byte) (int, *IOError) {
	n, err := c.conn.Write(b)
	if err != nil {
		return 0, NewIOErrorFromEnum(pb.IOError_IOERROR_UNKNOWN)
	}
	return n, nil
}

func (c *IORWWrapper) Flush() *IOError {
	return nil
}

func IOWrapRW(conn io.ReadWriter) IORWWrapper {
	return IORWWrapper{conn: conn}
}

// --8<-- [end:go_io_rw]

// Listener wraps `struct SandwichListener`.
type Listener struct {
	handle *C.struct_SandwichListener
}

// NewTunnelContext fills a Sandwich context from a protobuf configuration.
func NewListener(configuration *api.ListenerConfiguration) (*Listener, error) {
	out, err := proto.Marshal(configuration)
	if err != nil {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED, "")
	}

	n := len(out)
	if n == 0 {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_EMPTY, "")
	}

	listener := new(Listener)
	errc := C.sandwich_listener_new(unsafe.Pointer(&out[0]), C.size_t(n), &listener.handle)
	if errc != nil {
		err := createError(errc)
		C.sandwich_error_free(errc)
		return nil, err
	}

	runtime.SetFinalizer(listener, (*Listener).free)
	return listener, nil
}

// Reads implements the sandwich.IO interface for bufIO.
func (clistener *Listener) Listen() *IOError {
	listener := clistener.handle
	err := C.sandwich_listener_listen(listener)
	pb_err := pb.IOError(err)
	if pb_err != pb.IOError_IOERROR_OK {
		return NewIOErrorFromEnum(pb_err)
	}
	return nil
}

// Write implements the sandwich.IO interface for bufIO.
func (clistener *Listener) Accept() (*swOwnedIOWrapper, *IOError) {
	listener := clistener.handle
	owned_io := new(swOwnedIOWrapper)
	err := C.sandwich_listener_accept(listener, &(owned_io.handle))
	pb_err := pb.IOError(err)
	if pb_err != pb.IOError_IOERROR_OK {
		return nil, NewIOErrorFromEnum(pb_err)
	}
	runtime.SetFinalizer(owned_io, (*swOwnedIOWrapper).free)
	return owned_io, nil
}

func (clistener *Listener) Close() {
	listener := clistener.handle
	C.sandwich_listener_close(listener)
}

func (clistener *Listener) free() {
	listener := clistener.handle
	C.sandwich_listener_free(listener)
}

// Creates a Sandwich owned TCP based IO Object.
func IOTCPClient(hostname string, port uint16, is_blocking bool) (*swOwnedIOWrapper, *IOError) {
	var io *C.struct_SandwichIOOwned
	err := C.sandwich_io_client_tcp_new(C.CString(hostname), C.ushort(port), C.bool(is_blocking), &io)
	pb_err := pb.IOError(err)
	if pb_err != pb.IOError_IOERROR_OK {
		return nil, NewIOErrorFromEnum(pb_err)
	}
	client_io := new(swOwnedIOWrapper)
	client_io.handle = io
	runtime.SetFinalizer(client_io, (*swOwnedIOWrapper).free)
	return client_io, nil
}
