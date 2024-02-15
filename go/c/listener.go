// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package c

import (
	"runtime"
	"unsafe"
)

/*
  #include <stdbool.h>
  #include <stdint.h>
  #include "sandwich_c/listener.h"
*/
import "C"

// Listener wraps a C pointer to a Sandwich listener object.
type Listener struct {
	// handle is the C handle to the Sandwich listener object.
	handle *C.struct_SandwichListener
}

// free releases the memory occupied by a Sandwich listener.
func (listener *Listener) free() {
	if listener.handle != nil {
		listener.Close()
	}
	C.sandwich_listener_free(listener.handle)
	listener.handle = nil
}

// NewListener creates a new Sandwich listener.
func NewListener(serialized_configuration []byte) (*Listener, *Error) {
	listener := new(Listener)
	err := C.sandwich_listener_new(unsafe.Pointer(&serialized_configuration[0]), C.size_t(len(serialized_configuration)), &listener.handle)
	if err != nil {
		return nil, NewErrorFromPointer(err)
	}

	runtime.SetFinalizer(listener, (*Listener).free)
	return listener, nil
}

// Listen causes the Sandwich listener to start listening for connections.
func (listener *Listener) Listen() uint32 {
	return C.sandwich_listener_listen(listener.handle)
}

// Accept prompts the Sandwich listener to start accepting connections.
func (listener *Listener) Accept() (*OwnedIO, uint32) {
	var ownedIoHandle *C.struct_SandwichIOOwned = nil
	err := C.sandwich_listener_accept(listener.handle, &ownedIoHandle)
	if err != 0 {
		return nil, err
	}

	return newOwnedIOFromPointer(ownedIoHandle), 0
}

// Close closes the listener to new connections.
func (listener *Listener) Close() {
	C.sandwich_listener_close(listener.handle)
}
