// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package tunnel

import (
	"context"

	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	"io"

	api "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"

	sw "github.com/sandbox-quantum/sandwich/go"
	swc "github.com/sandbox-quantum/sandwich/go/c"
	swerrors "github.com/sandbox-quantum/sandwich/go/errors"
	swio "github.com/sandbox-quantum/sandwich/go/io"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

// TunnelIO represents the I/O interface used by tunnels in Sandwich.
type TunnelIO interface {
	// TunnelIO is an io.ReadWriter.
	io.ReadWriter

	// SetState sets the state of the tunnel.
	//
	// It is guaranteed that the state of the tunnel will not change between
	// two calls to SetState.
	SetState(tunnel_state pb.State)
}

// ownedIO is a wrapper around a swio.OwnedIO.
type ownedIO struct {
	// io is the original swio.OwnedIO.
	io *swio.OwnedIO
}

// Read implements io.Read.
func (io *ownedIO) Read(b []byte) (int, error) {
	return io.io.Read(b)
}

// Write implements io.Write.
func (io *ownedIO) Write(b []byte) (int, error) {
	return io.io.Write(b)
}

// SetState implements TunnelIO.
func (io *ownedIO) SetState(tunnelState pb.State) {}

// TunnelContext is a Sandwich context for tunnels.
type TunnelContext struct {
	// c is the C handle to the `struct SandwichContext *`.
	c *swc.TunnelContext
}

// NewTunnelContext fills a Sandwich context from a protobuf configuration.
func NewTunnelContext(handle *sw.Sandwich, configuration *api.Configuration) (*TunnelContext, error) {
	out, err := proto.Marshal(configuration)
	if err != nil {
		return nil, swerrors.NewProtobufError(pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED, "")
	}

	tunnelContext := new(TunnelContext)

	var cerr *swc.Error = nil
	tunnelContext.c, cerr = swc.NewTunnelContext(handle.GetCHandle(), out)
	if cerr != nil {
		return nil, swerrors.NewError(cerr)
	}

	return tunnelContext, nil
}

// Tunnel is a Sandwich tunnel.
type Tunnel struct {
	// c is the C handle to the `struct SandwichTunnel *`.
	c *swc.Tunnel

	// Tracer
	tracer *sw.SandwichTracer
}

// trampolineTunnelIO wraps a TunnelIO to make it compatible with the C package.
type trampolineTunnelIO struct {
	// tunnelIO is the tunnel IO.
	tunnelIO *TunnelIO
}

// trampolineTunnelIO implements io.Read.
func (trampoline *trampolineTunnelIO) Read(b []byte) (int, error) {
	return (*(trampoline.tunnelIO)).Read(b)
}

// trampolineTunnelIO implements io.Write.
func (trampoline *trampolineTunnelIO) Write(b []byte) (int, error) {
	return (*(trampoline.tunnelIO)).Write(b)
}

// trampolineTunnelIO implements swc.TunnelIO
func (trampoline *trampolineTunnelIO) SetState(tunnelState uint32) {
	(*(trampoline.tunnelIO)).SetState(pb.State(tunnelState))
}

// NewTunnel creates a Sandwich tunnel from a context, an io and a configuration.
func NewTunnel(ctx *TunnelContext, tunnelIO TunnelIO, configuration *api.TunnelConfiguration) (*Tunnel, error) {
	out, err := proto.Marshal(configuration)
	if err != nil {
		return nil, swerrors.NewProtobufError(pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED, "")
	}

	if len(out) == 0 {
		return nil, swerrors.NewProtobufError(pb.ProtobufError_PROTOBUFERROR_EMPTY, "")
	}

	cTunnel, cerr := ctx.c.NewTunnel(out, &trampolineTunnelIO{
		tunnelIO: &tunnelIO,
	},
	)

	if cerr != nil {
		return nil, swerrors.NewError(cerr)
	}

	return &Tunnel{
		c:      cTunnel,
		tracer: nil,
	}, nil
}

// wrappedReadWriter wraps an io.ReadWriter to turn it into a Sandwich IO.
type wrappedReadWriter struct {
	// readWriter is the original io.ReadWriter object.
	readWriter *io.ReadWriter
}

// Read implements io.Read.
func (wrw *wrappedReadWriter) Read(b []byte) (int, error) {
	return (*wrw.readWriter).Read(b)
}

// Write implements io.Write.
func (wrw *wrappedReadWriter) Write(b []byte) (int, error) {
	return (*wrw.readWriter).Write(b)
}

// SetState implements sandwich.TunnelIO.
func (wrw *wrappedReadWriter) SetState(tunnelState pb.State) {}

// NewTunnelWithReadWriter creates a Sandwich tunnel using a simple `io.ReadWriter` interface.
func NewTunnelWithReadWriter(ctx *TunnelContext, readWriter io.ReadWriter, configuration *api.TunnelConfiguration) (*Tunnel, error) {
	return NewTunnel(ctx, &wrappedReadWriter{
		readWriter: &readWriter,
	}, configuration)
}

// State returns the state of the tunnel.
func (tunnel *Tunnel) State() pb.State {
	return pb.State(tunnel.c.GetState())
}

// Handshakes performs or resumes the handshake stage.
// If nil is returned, it means the handshake is done.
func (tunnel *Tunnel) Handshake() error {
	state, err := tunnel.c.Handshake()
	if err != nil {
		return swerrors.NewError(err)
	}
	if int32(state) == int32(pb.HandshakeState_HANDSHAKESTATE_DONE) {
		return nil
	}
	return swerrors.NewHandshakeStateError(int32(state), "")
}

// Read implements the io.Reader interface.
func (tunnel *Tunnel) Read(b []byte) (int, error) {
	n, err := tunnel.c.Read(b)
	if int32(err) != int32(pb.RecordError_RECORDERROR_OK) {
		return 0, swerrors.NewRecordPlaneError(int32(err), "")
	}
	return n, nil
}

// Write implements the io.Reader interface.
func (tunnel *Tunnel) Write(b []byte) (int, error) {
	n, err := tunnel.c.Write(b)
	if int32(err) != int32(pb.RecordError_RECORDERROR_OK) {
		return 0, swerrors.NewRecordPlaneError(int32(err), "")
	}
	return n, nil
}

func (tunnel *Tunnel) SetTracer(ctx context.Context, tracer trace.Tracer) {
	tunnel.tracer = sw.NewSandwichTracer(ctx, tracer)
	tunnel.c.AttachTracer(tunnel.tracer.GetContextString(), tunnel.tracer.GetWriteBufFd())
}
