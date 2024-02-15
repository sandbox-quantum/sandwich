// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package c

/*
  #include <stdint.h>
  #include "sandwich_c/lib.h"
*/
import "C"

import (
	"runtime"
)

// Lib wraps a C pointer to a top-level Sandwich context.
type Lib struct {
	// handle is the C handle to the top-level Sandwich context.
	handle *C.struct_SandwichContext
}

// free releases the memory occupied by a top-level Sandwich context.
func (ctx *Lib) free() {
	C.sandwich_lib_context_free(ctx.handle)
	ctx.handle = nil
}

// NewLib creates a new Lib.
func NewLib() *Lib {
	lib := &Lib{
		handle: C.sandwich_lib_context_new(),
	}
	runtime.SetFinalizer(lib, (*Lib).free)
	return lib
}
