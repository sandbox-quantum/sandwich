// Copyright 2023 SandboxAQ
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

// io describes the Sandwich I/O interface.
// The I/O interface is used by the implementation to perform all i/o operation.
package sandwich

import (
	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
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
extern SandwichCIOCloseFunction sandwichGoIOClose;

typedef void* mutBuf;
typedef const void* constBuf;

static struct SandwichCIOSettings* allocSandwichCIOSettings(void) {
  return (struct SandwichCIOSettings*)calloc(1, sizeof(struct SandwichCIOSettings));
}

extern enum SandwichIOError sandwich_client_io_tcp_new(const char *hostname, const uint16_t port, bool async, struct SandwichCIOSettings **cio);
extern void sandwich_client_io_free(struct SandwichCIOSettings *cio);

static size_t client_bridge_read(SandwichCIOReadFunctionPtr read, void *uarg, void *buf, size_t count, enum SandwichTunnelState tunnel_state, enum SandwichIOError *err) {
	return read(uarg, buf, count, tunnel_state, err);
}

static size_t client_bridge_write(SandwichCIOWriteFunctionPtr write, void *uarg, void *buf, size_t count, enum SandwichTunnelState tunnel_state, enum SandwichIOError *err) {
	return write(uarg, buf, count, tunnel_state, err);
}

static void client_bridge_close(SandwichCIOCloseFunctionPtr close, void *uarg) {
	close(uarg);
}

*/
import "C"

// IO represents the I/O interface used by Sandwich.
type IO interface {
	// Read reads data from the connection.
	Read(b []byte, tunnel_state pb.State) (n int, err *IOError)

	// Write writes data from the connection.
	Write(b []byte, tunnel_state pb.State) (n int, err *IOError)

	// Close closes the connection.
	Close()
}

// createSettings creates a C-compatible structure from an IO interface.
func createSettings(goio *goIOWrapper) *C.struct_SandwichCIOSettings {
	set := C.allocSandwichCIOSettings()
	set.read = &C.sandwichGoIORead
	set.write = &C.sandwichGoIOWrite
	set.close = &C.sandwichGoIOClose
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

//export sandwichGoIOClose
func sandwichGoIOClose(ioint unsafe.Pointer) {
	io := *(*IO)(ioint)
	io.Close()
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

type swRawIOWrapper struct {
	settings *C.struct_SandwichCIOSettings
}

// Reads implements the sandwich.IO interface for bufIO.
func (client *swRawIOWrapper) Read(b []byte, tunnel_state pb.State) (int, *IOError) {
	settings := client.settings
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
func (client *swRawIOWrapper) Write(b []byte, tunnel_state pb.State) (int, *IOError) {
	settings := client.settings
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

// Close implements the sandwich.IO interface.
func (client *swRawIOWrapper) Close() {
	settings := client.settings
	C.client_bridge_close(settings.close, unsafe.Pointer(settings.uarg))
}

func (client *swRawIOWrapper) Free() {
	C.sandwich_client_io_free(client.settings)
}
func CreateTCPSettings(hostname string, port uint16, is_blocking bool) (*swRawIOWrapper, *IOError) {
	var io *C.struct_SandwichCIOSettings
	err := C.sandwich_client_io_tcp_new(C.CString(hostname), C.ushort(port), C.bool(is_blocking), &io)
	pb_err := pb.IOError(err)
	if pb_err != pb.IOError_IOERROR_OK {
		return nil, NewIOErrorFromEnum(pb_err)
	}
	client_io := new(swRawIOWrapper)
	client_io.settings = io
	return client_io, nil
}
