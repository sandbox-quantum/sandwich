// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package sandwich

import (
	swc "github.com/sandbox-quantum/sandwich/go/c"
)

// Sandwich is the top-level Sandwich context.
type Sandwich struct {
	// c is the C handle to the top-level Sandwich context.
	c *swc.Lib
}

// NewSandwich instantiates a new top-level context.
func NewSandwich() *Sandwich {
	return &Sandwich{
		c: swc.NewLib(),
	}
}
