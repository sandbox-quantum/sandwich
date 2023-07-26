// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sandwich

/*
  #include "sandwich_c/sandwich.h"
  #include <stdlib.h>
*/
import "C"

import (
	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	"runtime"
	"unsafe"

	api "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"

	"google.golang.org/protobuf/proto"
)

// Context wraps a `struct Context *` and exposes few methods
// for convenience.
type Context struct {
	// handle is the C handle to the `struct Context *`.
	handle *C.struct_SandwichContext
}

// createError creates a chain of errors, returned from Sandwich.
func createError(chain *C.struct_SandwichError) error {
	var root Error = nil
	var cur Error = nil
	for chain != nil {
		if _, ok := pb.ErrorKind_name[int32(chain.kind)]; ok {
			var e Error = nil
			var msg string = C.GoString(chain.msg)
			switch pb.ErrorKind(chain.kind) {
			case pb.ErrorKind_ERRORKIND_API:
				e = newAPIError(pb.APIError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_CONFIGURATION:
				e = newConfigurationError(pb.ConfigurationError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_TLS_CONFIGURATION:
				e = newTLSConfigurationError(pb.TLSConfigurationError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_CERTIFICATE:
				e = newCertificateError(pb.CertificateError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_SYSTEM:
				e = newSystemError(pb.SystemError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_SOCKET:
				e = newSocketError(pb.SocketError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_PROTOBUF:
				e = newProtobufError(pb.ProtobufError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_PRIVATE_KEY:
				e = newPrivateKeyError(pb.PrivateKeyError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_ASN1:
				e = newASN1Error(pb.ASN1Error(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_DATA_SOURCE:
				e = newDataSourceError(pb.DataSourceError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_KEM:
				e = newKEMError(pb.KEMError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_HANDSHAKE:
				e = newHandshakeError(pb.HandshakeError(chain.code), msg)
			}
			if root == nil {
				root = e
				cur = e
			} else {
				cur.setDetails(e)
				cur = e
			}
			chain = chain.details
		}
	}
	return root
}

// NewContext fills a Sandwich context from a protobuf configuration.
func NewContext(configuration *api.Configuration) (*Context, error) {
	out, err := proto.Marshal(configuration)
	if err != nil {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED, "")
	}

	n := len(out)
	if n == 0 {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_EMPTY, "")
	}

	ctx := new(Context)
	errc := C.sandwich_context_new(unsafe.Pointer(&out[0]), C.size_t(n), &ctx.handle)
	if errc != nil {
		err := createError(errc)
		C.sandwich_error_free(errc)
		return nil, err
	}

	runtime.SetFinalizer(ctx, (*Context).free)
	return ctx, nil
}

func (ctx *Context) free() {
	C.sandwich_context_free(ctx.handle)
	ctx.handle = nil
}

// Tunnel wraps a `struct SandwichTunnel *` and exposes its methods.
type Tunnel struct {
	// handle is the C handle to the `struct SandwichTunnel *`.
	handle *C.struct_SandwichTunnel

	// cIO is the I/O interface.
	cIO *cIO
}

// NewTunnel creates a Sandwich tunnel from a context, an io and a verifier.
func NewTunnel(ctx *Context, io IO, verifier *api.TunnelVerifier) (*Tunnel, error) {
	out, err := proto.Marshal(verifier)
	if err != nil {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED, "")
	}

	n := len(out)
	if n == 0 {
		return nil, newProtobufError(pb.ProtobufError_PROTOBUFERROR_EMPTY, "")
	}

	tun := new(Tunnel)
	tun.cIO = new(cIO)
	newcIO(tun.cIO, io)

	ver := C.struct_SandwichTunnelVerifierSerialized{
		src: unsafe.Pointer(&out[0]),
		n:   C.size_t(n),
	}

	errc := C.sandwich_tunnel_new(ctx.handle, tun.cIO.settings, ver, &tun.handle)
	if errc != nil {
		err := createError(errc)
		C.sandwich_error_free(errc)
		return nil, err
	}

	runtime.SetFinalizer(tun, (*Tunnel).free)
	return tun, nil
}

// State returns the state of the tunnel.
func (tun *Tunnel) State() pb.State {
	state := C.sandwich_tunnel_state(tun.handle)
	return pb.State(state)
}

// Handshakes performs or resumes the handshake stage.
// If nil is returned, it means the handshake is done.
func (tun *Tunnel) Handshake() error {
	var state uint32 = 0
	errc := C.sandwich_tunnel_handshake(tun.handle, &state)
	if errc != nil {
		err := createError(errc)
		C.sandwich_error_free(errc)
		return err
	}
	if int32(state) == int32(pb.HandshakeState_HANDSHAKESTATE_DONE) {
		return nil
	}
	return newHandshakeStateError(int32(state), "")
}

// Read implements the io.Reader interface.
func (tun *Tunnel) Read(b []byte) (int, error) {
	var read_n C.size_t = 0
	err := C.sandwich_tunnel_read(tun.handle, unsafe.Pointer(&b[0]),
		C.size_t(len(b)),
		&read_n)
	if int32(err) != int32(pb.RecordError_RECORDERROR_OK) {
		return 0, newRecordPlaneError(int32(err), "")
	}
	return int(read_n), nil
}

// Write implements the io.Reader interface.
func (tun *Tunnel) Write(b []byte) (int, error) {
	var write_n C.size_t = 0
	err := C.sandwich_tunnel_write(tun.handle, unsafe.Pointer(&b[0]),
		C.size_t(len(b)),
		&write_n)
	if int32(err) != int32(pb.RecordError_RECORDERROR_OK) {
		return 0, newRecordPlaneError(int32(err), "")
	}
	return int(write_n), nil
}

// Close closes the tunnel.
func (tun *Tunnel) Close() error {
	C.sandwich_tunnel_close(tun.handle)
	return nil
}

// IO returns the IO interface used by a tunnel.
// The interface is borrowed to the user. Its ownership remains to the Tunnel.
func (tun *Tunnel) IO() *IO {
	return tun.cIO.io
}

// free frees the memory allocated for a `struct SandwichTunnel*`.
func (tun *Tunnel) free() {
	C.sandwich_tunnel_free(tun.handle)
}
