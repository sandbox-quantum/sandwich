// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// io describes the Sandwich I/O interface.
// The I/O interface is used by the implementation to perform all i/o operation.
package io

import (
	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	swc "github.com/sandbox-quantum/sandwich/go/c"
	swerrors "github.com/sandbox-quantum/sandwich/go/errors"
	"io"
)

// IO is a Sandwich IO.
type IO struct {
	// c is the C handle to the Sandwich IO.
	c *swc.IO
}

// NewIO creates a new IO from a io.ReadWriter
func NewIO(readWriter io.ReadWriter) *IO {
	return &IO{
		c: swc.NewIO(readWriter),
	}
}

// OwnedIO is a Sandwich IO owned by Sandwich.
type OwnedIO struct {
	// c is the C handle to the owned Sandwich IO.
	c *swc.OwnedIO
}

// Read implements io.Read.
func (ownedIO *OwnedIO) Read(b []byte) (int, error) {
	n, err := ownedIO.c.Read(b)
	if err != uint32(pb.IOError_IOERROR_OK) {
		return 0, swerrors.NewIOErrorFromEnum(pb.IOError(err))
	}
	return n, nil
}

// Write implements io.Write.
func (ownedIO *OwnedIO) Write(b []byte) (int, error) {
	n, err := ownedIO.c.Write(b)
	if err != uint32(pb.IOError_IOERROR_OK) {
		return 0, swerrors.NewIOErrorFromEnum(pb.IOError(err))
	}
	return n, nil
}

// Creates a Sandwich owned TCP based IO Object.
func IOTCPClient(hostname string, port uint16) (*OwnedIO, *swerrors.IOError) {
	ownedIO, err := swc.NewOwnedIOTCPClient(hostname, port)
	pbErr := pb.IOError(err)
	if pbErr != pb.IOError_IOERROR_OK {
		return nil, swerrors.NewIOErrorFromEnum(pbErr)
	}
	return &OwnedIO{
		c: ownedIO,
	}, nil
}

// Creates a Sandwich owned Turbo based IO Object.
func IOTurboClient(udp_hostname string, udp_port uint16, tcp_hostname string, tcp_port uint16) (*OwnedIO, *swerrors.IOError) {
	ownedIO, err := swc.NewOwnedIOTurboClient(udp_hostname, udp_port, tcp_hostname, tcp_port)
	pbErr := pb.IOError(err)
	if pbErr != pb.IOError_IOERROR_OK {
		return nil, swerrors.NewIOErrorFromEnum(pbErr)
	}
	return &OwnedIO{
		c: ownedIO,
	}, nil
}
