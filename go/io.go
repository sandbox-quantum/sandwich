// io describes the Sandwich I/O interface.
// The I/O interface is used by the implementation to perform all i/o operation.
package sandwich

import (
	"runtime"
	"unsafe"

	pb "github.com/sandbox-quantum/sandwich/proto/sandwich"
)

/*
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include "c/sandwich.h"


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
func createSettings(io IO) *C.struct_SandwichCIOSettings {
	set := C.allocSandwichCIOSettings()
	set.read = &C.sandwichGoIORead
	set.write = &C.sandwichGoIOWrite
	set.close = &C.sandwichGoIOClose
	set.uarg = unsafe.Pointer(&io)
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

// cIOHandle wraps `struct SandwichCIO`.
type cIOHandle struct {
	handle *C.struct_SandwichCIO
	io     *IO
}

// newcIOHandle creates a new cIOHandle from an IO interface.
func newcIOHandle(handle *cIOHandle, io IO) *GlobalError {
	settings := createSettings(io)
	defer C.free(unsafe.Pointer(settings))

	err := C.sandwich_io_new(settings, &handle.handle)
	if int32(err) != int32(pb.Error_ERROR_OK) {
		return newGlobalError(int32(err))
	}
	handle.io = &io

	runtime.SetFinalizer(handle, (*cIOHandle).free)
	return nil
}

// Free releases the memory taken by `struct SandwichCIO.
func (handle *cIOHandle) free() {
	C.sandwich_io_free(handle.handle)
	handle.handle = nil
}
