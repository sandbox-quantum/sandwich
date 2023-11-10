// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package sandwich

/*
  #include <stdbool.h>
  #include <stdint.h>
  #include "sandwich_c/io.h"
  #include "sandwich_c/sandwich.h"
  #include "sandwich_c/listener.h"
  #include <stdlib.h>
*/
import "C"

import (
	"runtime"
)

// Sandwich wraps a `struct SandwichContext *`, which is the top-level context
// of the Sandwich library.
type Sandwich struct {
	// handle is the C handle to the `struct SandwichContext *`.
	handle *C.struct_SandwichContext
}

// NewSandwich instantiates a new top-level context.
func NewSandwich() *Sandwich {
	sw := new(Sandwich)
	sw.handle = C.sandwich_lib_context_new()

	runtime.SetFinalizer(sw, (*Sandwich).free)
	return sw
}

func (sw *Sandwich) free() {
	C.sandwich_lib_context_free(sw.handle)
	sw.handle = nil
}
