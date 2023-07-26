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
	"runtime"
	"unsafe"

	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
)

/*
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
func createSettings(cio *cIO) *C.struct_SandwichCIOSettings {
	set := C.allocSandwichCIOSettings()
	set.read = &C.sandwichGoIORead
	set.write = &C.sandwichGoIOWrite
	set.close = &C.sandwichGoIOClose
	set.uarg = unsafe.Pointer(cio.io)
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

// cIO wraps `struct SandwichCIOSettings` and `IO` together.
type cIO struct {
	settings *C.struct_SandwichCIOSettings
	io       *IO
}

// newcIO creates a new SandwichCIOSettings from an IO interface.
func newcIO(cio *cIO, io IO) {
	cio.io = &io
	cio.settings = createSettings(cio)
	runtime.SetFinalizer(cio, (*cIO).free)
}

// free releases the memory taken by `struct SandwichCIOSettings`.
func (cio *cIO) free() {
	C.free(unsafe.Pointer(cio.settings))
	cio.settings = nil
}
