// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package c

/*
  #include <stdbool.h>
  #include <stdint.h>
  #include <stdlib.h>
  #include "sandwich_c/lib.h"
  #include "sandwich_c/tunnel.h"

  typedef void* mutBuf;
  typedef const void* constBuf;

  extern SandwichIOReadFunction sandwichGoTunnelIORead;
  extern SandwichIOWriteFunction sandwichGoTunnelIOWrite;
  extern SandwichTunnelIOSetStateFunction sandwichGoTunnelSetState;

  static struct SandwichTunnelIO* allocSandwichTunnelIO(void) {
    return (struct SandwichTunnelIO*)calloc(1, sizeof(struct SandwichTunnelIO));
  }
*/
import "C"

import (
	"io"
	"runtime"
	"unsafe"
)

//export sandwichGoTunnelIORead
func sandwichGoTunnelIORead(uarg unsafe.Pointer, buf C.mutBuf, size C.size_t, err *C.enum_SandwichIOError) C.size_t {
	tunnelIO := *(*TunnelIO)(uarg)

	*err = C.enum_SandwichIOError(0)
	n, ioErr := tunnelIO.Read(unsafe.Slice((*byte)(buf), int(size)))
	if ioErr != nil {
		*err = kUnknownIOError
	}
	return C.size_t(n)
}

//export sandwichGoTunnelIOWrite
func sandwichGoTunnelIOWrite(uarg unsafe.Pointer, buf C.constBuf, size C.size_t, err *C.enum_SandwichIOError) C.size_t {
	tunnelIO := *(*TunnelIO)(uarg)

	*err = C.enum_SandwichIOError(0)
	n, ioErr := tunnelIO.Write(unsafe.Slice((*byte)(buf), int(size)))
	if ioErr != nil {
		*err = kUnknownIOError
	}
	return C.size_t(n)
}

//export sandwichGoTunnelSetState
func sandwichGoTunnelSetState(uarg unsafe.Pointer, tunnelState C.enum_SandwichTunnelState) {
	tunnelIO := *(*TunnelIO)(uarg)

	tunnelIO.SetState(tunnelState)
}

// TunnelIO wraps a Sandwich tunnel IO.
type TunnelIO interface {
	// TunnelIOInterface is a io.ReadWriter
	io.ReadWriter

	// SetState sets the state of the tunnel.
	//
	// It is guaranteed that the state of the tunnel will not change between
	// two calls to SetState.
	SetState(tunnelState uint32)
}

// tunnelIOWrapper wraps a Sandwich tunnel IO.
type tunnelIOWrapper struct {
	// tunnelIO is the TunnelIO attached to the Sandwich tunnel IO.
	tunnelIO *TunnelIO

	// handle is the C handle to the Sandwich tunnel IO.
	handle *C.struct_SandwichTunnelIO
}

// free releases the memory occuiped by a tunnelIOWrapper.
func (wrapper *tunnelIOWrapper) free() {
	C.free(unsafe.Pointer(wrapper.handle))
	wrapper.handle = nil
}

// newTunnelIOWrapper creates a new tunnelIOWrapper.
func newTunnelIOWrapper(tunnelIO TunnelIO) *tunnelIOWrapper {
	handle := C.allocSandwichTunnelIO()
	handle.base.read = &C.sandwichGoTunnelIORead
	handle.base.write = &C.sandwichGoTunnelIOWrite
	handle.base.flush = nil
	handle.base.uarg = unsafe.Pointer(&tunnelIO)
	handle.set_state = &C.sandwichGoTunnelSetState

	wrapper := &tunnelIOWrapper{
		tunnelIO: &tunnelIO,
		handle:   handle,
	}

	runtime.SetFinalizer(wrapper, (*tunnelIOWrapper).free)
	return wrapper
}
