// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// io describes the Sandwich I/O interface.
// The I/O interface is used by the implementation to perform all i/o operation.
package io

import (
	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	api "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"
	swc "github.com/sandbox-quantum/sandwich/go/c"
	swerrors "github.com/sandbox-quantum/sandwich/go/errors"

	"google.golang.org/protobuf/proto"
)

// Listener is a listener that accepts connections and returns IOs.
type Listener struct {
	// c is the C handle to the Sandwich listener.
	c *swc.Listener
}

// NewListener creates a new Sandwich listener from a protobuf configuration.
func NewListener(configuration *api.ListenerConfiguration) (*Listener, error) {
	out, err := proto.Marshal(configuration)
	if err != nil {
		return nil, swerrors.NewProtobufError(pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED, "")
	}

	if len(out) == 0 {
		return nil, swerrors.NewProtobufError(pb.ProtobufError_PROTOBUFERROR_EMPTY, "")
	}

	listener := new(Listener)
	var cerr *swc.Error = nil
	listener.c, cerr = swc.NewListener(out)
	if cerr != nil {
		return nil, swerrors.NewError(cerr)
	}
	return listener, nil
}

// Reads implements the sandwich.IO interface for bufIO.
func (listener *Listener) Listen() *swerrors.IOError {
	err := listener.c.Listen()
	pbErr := pb.IOError(err)
	if pbErr != pb.IOError_IOERROR_OK {
		return swerrors.NewIOErrorFromEnum(pbErr)
	}
	return nil
}

// Write implements the sandwich.IO interface for bufIO.
func (listener *Listener) Accept() (*OwnedIO, *swerrors.IOError) {
	ownedIO, err := listener.c.Accept()
	pbErr := pb.IOError(err)
	if pbErr != pb.IOError_IOERROR_OK {
		return nil, swerrors.NewIOErrorFromEnum(pbErr)
	}
	return &OwnedIO{
		c: ownedIO,
	}, nil
}

func (listener *Listener) Close() {
	listener.c.Close()
}
