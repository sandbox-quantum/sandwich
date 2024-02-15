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
  #include "sandwich_c/io.h"

  typedef void* mutBuf;
  typedef const void* constBuf;

  static size_t sandwich_owned_io_client_bridge_read(SandwichIOReadFunctionPtr read, void *uarg, void *buf, size_t count, enum SandwichIOError *err) {
    return read(uarg, buf, count, err);
  }

  static size_t sandwich_owned_io_client_bridge_write(SandwichIOWriteFunctionPtr write, void *uarg, void *buf, size_t count, enum SandwichIOError *err) {
    return write(uarg, buf, count, err);
  }

*/
import "C"

// OwnedIO wraps a C pointer to a Sandwich owned IO.
type OwnedIO struct {
	// handle is the C handle to the Sandwich owned IO.
	handle *C.struct_SandwichIOOwned
}

// free releases the memory occupied by a Sandwich owned IO.
func (ownedIO *OwnedIO) free() {
	C.sandwich_io_owned_free(ownedIO.handle)
	ownedIO.handle = nil
}

// newOwnedIOFromPointer creates a new Sandwich owned IO from a pointer.
func newOwnedIOFromPointer(handle *C.struct_SandwichIOOwned) *OwnedIO {
	ownedIo := &OwnedIO{
		handle: handle,
	}

	runtime.SetFinalizer(ownedIo, (*OwnedIO).free)
	return ownedIo
}

// Read reads some data from the owned IO.
func (ownedIO *OwnedIO) Read(buf []byte) (int, uint32) {
	var err uint32 = 0
	n := C.sandwich_owned_io_client_bridge_read(ownedIO.handle.io.read, ownedIO.handle.io.uarg, unsafe.Pointer(&buf[0]), C.size_t(len(buf)), &err)
	if err != 0 {
		return 0, err
	}
	return int(n), err
}

// Write writes some data to the owned IO.
func (ownedIO *OwnedIO) Write(buf []byte) (int, uint32) {
	var err uint32 = 0
	n := C.sandwich_owned_io_client_bridge_write(ownedIO.handle.io.write, ownedIO.handle.io.uarg, unsafe.Pointer(&buf[0]), C.size_t(len(buf)), &err)
	if err != 0 {
		return 0, err
	}
	return int(n), err
}

// NewOwnedIOTCPClient creates a new Sandwich owned IO using a TCP client.
func NewOwnedIOTCPClient(hostname string, port uint16, isBlocking bool) (*OwnedIO, uint32) {
	var handle *C.struct_SandwichIOOwned = nil
	err := C.sandwich_io_client_tcp_new(C.CString(hostname), C.ushort(port), C.bool(isBlocking), &handle)
	if err != 0 {
		return nil, err
	}
	return newOwnedIOFromPointer(handle), err
}
