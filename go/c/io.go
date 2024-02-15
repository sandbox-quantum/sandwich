// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package c

/*
  #include <stdbool.h>
  #include <stdint.h>
  #include <stdlib.h>
  #include "sandwich_c/io.h"

  typedef void* mutBuf;
  typedef const void* constBuf;

  extern SandwichIOReadFunction sandwichGoIORead;
  extern SandwichIOWriteFunction sandwichGoIOWrite;

  static struct SandwichIO* allocSandwichIO(void) {
    return (struct SandwichIO*)calloc(1, sizeof(struct SandwichIO));
  }
*/
import "C"

import (
	"io"
	"runtime"
	"unsafe"
)

const kUnknownIOError C.enum_SandwichIOError = 6

//export sandwichGoIORead
func sandwichGoIORead(uarg unsafe.Pointer, buf C.mutBuf, size C.size_t, err *C.enum_SandwichIOError) C.size_t {
	readWriter := *(*io.ReadWriter)(uarg)

	*err = C.enum_SandwichIOError(0)
	n, ioErr := readWriter.Read(unsafe.Slice((*byte)(buf), int(size)))
	if ioErr != nil {
		*err = kUnknownIOError
	}
	return C.size_t(n)
}

//export sandwichGoIOWrite
func sandwichGoIOWrite(uarg unsafe.Pointer, buf C.constBuf, size C.size_t, err *C.enum_SandwichIOError) C.size_t {
	readWriter := *(*io.ReadWriter)(uarg)

	*err = C.enum_SandwichIOError(0)
	n, ioErr := readWriter.Write(unsafe.Slice((*byte)(buf), int(size)))
	if ioErr != nil {
		*err = kUnknownIOError
	}
	return C.size_t(n)
}

// Io wraps a SandwichIO structure.
type IO struct {
	// readWriter is the readWriter attached to the IO.
	readWriter *io.ReadWriter

	// handle is the C handle to the SandwichIO structure.
	handle *C.struct_SandwichIO
}

// free releases the memory occupied by an IO.
func (io *IO) free() {
	C.free(unsafe.Pointer(io.handle))
	io.handle = nil
}

// NewIO creates a new IO structure.
func NewIO(readWriter io.ReadWriter) *IO {
	handle := C.allocSandwichIO()
	handle.read = &C.sandwichGoIORead
	handle.write = &C.sandwichGoIOWrite
	handle.flush = nil
	handle.uarg = unsafe.Pointer(&readWriter)
	ioObject := &IO{
		readWriter: &readWriter,
		handle:     handle,
	}

	runtime.SetFinalizer(ioObject, (*IO).free)
	return ioObject
}
