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
  #include "sandwich_c/tunnel.h"

  typedef void* mutBuf;
  typedef const void* constBuf;

  static size_t sandwich_owned_io_client_bridge_read(SandwichIOReadFunctionPtr read, void *uarg, void *buf, size_t count, enum SandwichIOError *err) {
    return read(uarg, buf, count, err);
  }

  static size_t sandwich_owned_io_client_bridge_write(SandwichIOWriteFunctionPtr write, void *uarg, void *buf, size_t count, enum SandwichIOError *err) {
    return write(uarg, buf, count, err);
  }

  static void sandwich_tunnel_io_client_bridge_set_state(SandwichTunnelIOSetStateFunctionPtr set_state, void *uarg, enum SandwichTunnelState tunnel_state) {
    set_state(uarg, tunnel_state);
  }

  #ifdef SANDWICHTURBO
  #include "sandwich_c/turbo.h"
  static inline bool turbo_enabled(void) {
    return true;
  }
  #else
  static bool turbo_enabled(void) {
    return false;
  }
  static enum SandwichIOError
  sandwich_io_client_turbo_new(const char *udp_hostname, const uint16_t udp_port,
                               const char *tcp_hostname, const uint16_t tcp_port,
                               bool is_blocking, struct SandwichIOOwned **ownedIO) {
    return SANDWICH_IOERROR_UNKNOWN;
  }
  #endif
*/
import "C"

// OwnedIO wraps a C pointer to a Sandwich owned IO.
type OwnedIO struct {
	// handle is the C handle to the Sandwich owned IO.
	handle *C.struct_SandwichIOOwned

	// sets the tunnel state if IO is being used with tunnels.
	set_state C.SandwichTunnelIOSetStateFunctionPtr
}

// free releases the memory occupied by a Sandwich owned IO.
func (ownedIO *OwnedIO) free() {
	C.sandwich_io_owned_free(ownedIO.handle)
	ownedIO.handle = nil
}

// newOwnedIOFromPointer creates a new Sandwich owned IO from a pointer.
func newOwnedIOFromPointer(handle *C.struct_SandwichIOOwned) *OwnedIO {
	tun_io := C.sandwich_owned_io_to_tunnel_io(handle)
	ownedIo := &OwnedIO{
		handle:    handle,
		set_state: tun_io.set_state,
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

// Set the tunnelIO's state.
func (ownedIO *OwnedIO) SetState(tunnelState uint32) {
	if ownedIO.set_state != nil {
		C.sandwich_tunnel_io_client_bridge_set_state(ownedIO.set_state, ownedIO.handle.io.uarg, tunnelState)
	}
}

// NewOwnedIOTCPClient creates a new client side Sandwich IO using TCP.
func NewOwnedIOTCPClient(hostname string, port uint16, isBlocking bool) (*OwnedIO, uint32) {
	var handle *C.struct_SandwichIOOwned = nil
	err := C.sandwich_io_client_tcp_new(C.CString(hostname), C.ushort(port), C.bool(isBlocking), &handle)
	if err != 0 {
		return nil, err
	}
	return newOwnedIOFromPointer(handle), err
}

// NewOwnedIOTurboClient creates a new client side Sandwich IO using Turbo transport.
func NewOwnedIOTurboClient(udp_hostname string, udp_port uint16, tcp_hostname string, tcp_port uint16, isBlocking bool) (*OwnedIO, uint32) {
	if C.turbo_enabled() {
		var handle *C.struct_SandwichIOOwned = nil
		err := C.sandwich_io_client_turbo_new(C.CString(udp_hostname), C.ushort(udp_port), C.CString(tcp_hostname), C.ushort(tcp_port), C.bool(isBlocking), &handle)
		if err != 0 {
			return nil, err
		}
		return newOwnedIOFromPointer(handle), err
	} else {
		return nil, kUnknownIOError
	}
}
