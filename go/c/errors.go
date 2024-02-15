// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package c

/*
  #include <stdint.h>
  #include "sandwich_c/error.h"
*/
import "C"

import (
	"runtime"
)

// Error wraps a C pointer to an error.
type Error struct {
	// handle holds the C handle to an error.
	handle *C.struct_SandwichError
}

// free releases the memory occupied by a Sandwich error object.
func (e *Error) free() {
	C.sandwich_error_free(e.handle)
	e.handle = nil
}

// NewErrorFromPointer creates a new Error from a pointer.
func NewErrorFromPointer(e *C.struct_SandwichError) *Error {
	if e != nil {
		err := &Error{
			handle: e,
		}
		runtime.SetFinalizer(err, (*Error).free)

		return err
	}
	return nil
}

// GetMsg returns the error string, or "nil" if no error string is found with
// this error.
func (e *Error) GetMsg() string {
	if e.handle.msg != nil {
		return C.GoString(e.handle.msg)
	}
	return "nil"
}

// GetKind returns the kind of error.
func (e *Error) GetKind() uint32 {
	return uint32(e.handle.kind)
}

// GetCode returns the code of error.
func (e *Error) GetCode() uint32 {
	return uint32(e.handle.code)
}

// GetDetails returns the encapsulated error, if any.
func (e *Error) GetDetails() *Error {
	if e.handle.details != nil {
		return &Error{
			handle: e.handle.details,
		}
	}
	return nil
}
