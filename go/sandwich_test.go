// Copyright 2022 SandboxAQ
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

package sandwich_test

import (
	"bytes"
	"github.com/sandbox-quantum/sandwich/go"
	"crypto/rand"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/bazelbuild/rules_go/go/tools/bazel"

	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"

	api "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"
)

var testCertPattern = "testdata/%s.cert.pem"

var (
	pingMsg                = [...]byte{'P', 'I', 'N', 'G'}
	pongMsg                = [...]byte{'P', 'O', 'N', 'G'}
	certPath        string = "testdata/localhost.cert.pem"
	certExpiredPath string = "testdata/cert_expired.pem"
	keyPath         string = "testdata/localhost.key.pem"
	keyExpiredPath  string = "testdata/private_key_cert_expired.pem"
)

// bufIO implements sandwich.IO, using a TX buffer and a
// remote peer.
type bufIO struct {
	tx     bytes.Buffer
	remote *bufIO
}

// newBufIO Creates a new buffer IO.
func newBufIO() *bufIO {
	return new(bufIO)
}

// Reads implements the sandwich.IO interface for bufIO.
func (buf *bufIO) Read(b []byte, tunnel_state pb.State) (int, *sandwich.IOError) {
	if buf.tx.Len() == 0 {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_WOULD_BLOCK)
	}
	n, err := buf.tx.Read(b)
	if err != nil {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_UNKNOWN)
	}
	if n == 0 {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_WOULD_BLOCK)
	}
	return n, nil
}

// Write implements the sandwich.IO interface for bufIO.
func (buf *bufIO) Write(b []byte, tunnel_state pb.State) (int, *sandwich.IOError) {
	n, err := buf.remote.tx.Write(b)
	if err != nil {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_UNKNOWN)
	}
	if n == 0 {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_WOULD_BLOCK)
	}
	return n, nil
}

// Close implements the sandwich.IO interface.
func (buf *bufIO) Close() {
}

// createServerConfiguration creates the configuration for the server.
func createServerConfiguration(t *testing.T) (*api.Configuration, error) {
	certfile, err := bazel.Runfile(certPath)
	if err != nil {
		t.Errorf("Could not load certificate file %s: %v", certPath, err)
	}
	keyfile, err := bazel.Runfile(keyPath)
	if err != nil {
		t.Errorf("Could not load private key file %s: %v", keyPath, err)
	}

	return &api.Configuration{
		Impl: api.Implementation_IMPL_OPENSSL1_1_1_OQS,
		Opts: &api.Configuration_Server{
			Server: &api.ServerOptions{
				Opts: &api.ServerOptions_Tls{
					Tls: &api.TLSServerOptions{
						CommonOptions: &api.TLSOptions{
							Kem: []string{
								"kyber1024",
							},
							PeerVerifier: &api.TLSOptions_EmptyVerifier{
								EmptyVerifier: &api.EmptyVerifier{},
							},
							Identity: &api.X509Identity{
								Certificate: &api.Certificate{
									Source: &api.Certificate_Static{
										Static: &api.ASN1DataSource{
											Data: &api.DataSource{
												Specifier: &api.DataSource_Filename{
													Filename: certfile,
												},
											},
											Format: api.ASN1EncodingFormat_ENCODING_FORMAT_PEM,
										},
									},
								},
								PrivateKey: &api.PrivateKey{
									Source: &api.PrivateKey_Static{
										Static: &api.ASN1DataSource{
											Data: &api.DataSource{
												Specifier: &api.DataSource_Filename{
													Filename: keyfile,
												},
											},
											Format: api.ASN1EncodingFormat_ENCODING_FORMAT_PEM,
										},
									},
								},
							},
							AlpnProtocol: []string{
								"http/1.1",
								"h2",
								"h2c",
								"h3",
							},
						},
					},
				},
			},
		},
	}, nil
}

// createClientConfiguration creates the configuration for the client.
func createClientConfiguration(t *testing.T) (*api.Configuration, error) {
	certfile, err := bazel.Runfile(certPath)
	if err != nil {
		t.Errorf("Could not load certificate file %s: %v", certPath, err)
	}

	return &api.Configuration{
		Impl: api.Implementation_IMPL_OPENSSL1_1_1_OQS,
		Opts: &api.Configuration_Client{
			Client: &api.ClientOptions{
				Opts: &api.ClientOptions_Tls{
					Tls: &api.TLSClientOptions{
						CommonOptions: &api.TLSOptions{
							Kem: []string{
								"kyber1024",
							},
							PeerVerifier: &api.TLSOptions_X509Verifier{
								X509Verifier: &api.X509Verifier{
									TrustedCas: []*api.Certificate{
										{
											Source: &api.Certificate_Static{
												Static: &api.ASN1DataSource{
													Data: &api.DataSource{
														Specifier: &api.DataSource_Filename{
															Filename: certfile,
														},
													},
													Format: api.ASN1EncodingFormat_ENCODING_FORMAT_PEM,
												},
											},
										},
									},
								},
							},
							AlpnProtocol: []string{
								"http/1.1",
								"h2",
								"h2c",
								"h3",
							},
						},
					},
				},
			},
		},
	}, nil
}

// createServerContext creates the server context.
func createServerContext(t *testing.T) (*sandwich.Context, error) {
	config, err := createServerConfiguration(t)
	if err != nil {
		t.Errorf("Failed to create the server configuration: %v", err)
		panic("failed")
	}

	ctx, err := sandwich.NewContext(config)
	if err != nil {
		t.Errorf("Failed to create the server context: %v", err)
		panic("failed")
	}

	return ctx, nil
}

// createClientContext creates the client context.
func createClientContext(t *testing.T) (*sandwich.Context, error) {
	config, err := createClientConfiguration(t)
	if err != nil {
		t.Errorf("Failed to create the client configuration: %v", err)
		panic("failed")
	}

	ctx, err := sandwich.NewContext(config)
	if err != nil {
		t.Errorf("Failed to create the client context: %v", err)
	}

	return ctx, nil
}

type ioInts struct {
	client sandwich.IO
	server sandwich.IO
}

// createServerClientIOs creates the I/O interfaces for the server and the client.
func createIOs() ioInts {
	client := newBufIO()
	server := newBufIO()
	client.remote = server
	server.remote = client
	return ioInts{
		client: client,
		server: server,
	}
}

// createServerTunnel creates the tunnel for the server.
func createServerTunnel(t *testing.T, context *sandwich.Context, io sandwich.IO) (*sandwich.Tunnel, error) {
	tun, err := sandwich.NewTunnel(context, io, createEmptyTunnelVerifier())
	if err != nil {
		t.Errorf("Failed to create the server's tunnel: %v", err)
	}

	return tun, nil
}

// createClientTunnel creates the tunnel for the client.
func createClientTunnel(t *testing.T, context *sandwich.Context, io sandwich.IO) (*sandwich.Tunnel, error) {
	tun, err := sandwich.NewTunnel(context, io, createEmptyTunnelVerifier())
	if err != nil {
		t.Errorf("Failed to create the client's tunnel: %v", err)
	}

	return tun, nil
}

func TestTunnels(t *testing.T) {
	serverContext, err := createServerContext(t)
	if err != nil {
		t.Errorf("Failed to create Server context: %v", err)
	}

	clientContext, err := createClientContext(t)
	if err != nil {
		t.Errorf("Failed to create Client context: %v", err)
	}

	ioInterfaces := createIOs()

	serverTunnel, err := createServerTunnel(t, serverContext, ioInterfaces.server)
	if err != nil {
		t.Errorf("Failed to create the server tunnel: %v", err)
	}

	clientTunnel, err := createClientTunnel(t, clientContext, ioInterfaces.client)
	if err != nil {
		t.Errorf("Failed to create the server tunnel: %v", err)
	}

	err = clientTunnel.Handshake()
	if err == nil {
		t.Errorf("Expected errHanshake not nil, got nil")
	}
	if handshakeErr, ok := err.(*sandwich.HandshakeStateError); ok {
		if handshakeErr.Code() != int32(pb.HandshakeState_HANDSHAKESTATE_WANT_READ) {
			t.Errorf("Expected WANT_READ, got %v", err)
		}
	} else {
		t.Errorf("Bad type for `error`")
	}

	err = serverTunnel.Handshake()
	if err == nil {
		t.Errorf("Expected errHanshake not nil, got nil")
	}
	if handshakeErr, ok := err.(*sandwich.HandshakeStateError); ok {
		if handshakeErr.Code() != int32(pb.HandshakeState_HANDSHAKESTATE_WANT_READ) {
			t.Errorf("Expected WANT_READ, got %v", err)
		}
	} else {
		t.Errorf("Bad type for `error`")
	}

	err = clientTunnel.Handshake()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	err = serverTunnel.Handshake()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	n, err := clientTunnel.Write(pingMsg[:])
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if n != len(pingMsg) {
		t.Errorf("Expected %v bytes sent, got %v", len(pingMsg), n)
	}

	var buf [len(pingMsg)]byte
	n, err = serverTunnel.Read(buf[:])
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if n != len(pingMsg) {
		t.Errorf("Expected %v bytes read, got %v", len(pingMsg), n)
	}
	if buf != pingMsg {
		t.Errorf("Expected %v, got %v", pingMsg, buf)
	}

	n, err = serverTunnel.Write(pongMsg[:])
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if n != len(pongMsg) {
		t.Errorf("Expected %v bytes sent, got %v", len(pongMsg), n)
	}

	n, err = clientTunnel.Read(buf[:])
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if n != len(pongMsg) {
		t.Errorf("Expected %v bytes read, got %v", len(pongMsg), n)
	}
	if buf != pongMsg {
		t.Errorf("Expected %v, got %v", pongMsg, buf)
	}

	clientTunnel.Close()
	serverTunnel.Close()
}

func TestTunnelLargeReadWriteGC(t *testing.T) {
	serverContext, err := createServerContext(t)
	if err != nil {
		t.Errorf("Failed to create Server context: %v", err)
	}

	clientContext, err := createClientContext(t)
	if err != nil {
		t.Errorf("Failed to create Client context: %v", err)
	}

	ioInterfaces := createIOs()

	serverTunnel, err := createServerTunnel(t, serverContext, ioInterfaces.server)
	if err != nil {
		t.Errorf("Failed to create the server tunnel: %v", err)
	}

	clientTunnel, err := createClientTunnel(t, clientContext, ioInterfaces.client)
	if err != nil {
		t.Errorf("Failed to create the server tunnel: %v", err)
	}

	err = clientTunnel.Handshake()
	if err == nil {
		t.Errorf("Expected errHanshake not nil, got nil")
	}
	if handshakeErr, ok := err.(*sandwich.HandshakeStateError); ok {
		if handshakeErr.Code() != int32(pb.HandshakeState_HANDSHAKESTATE_WANT_READ) {
			t.Errorf("Expected WANT_READ, got %v", err)
		}
	} else {
		t.Errorf("Bad type for `error`")
	}

	err = serverTunnel.Handshake()
	if err == nil {
		t.Errorf("Expected errHanshake not nil, got nil")
	}
	if handshakeErr, ok := err.(*sandwich.HandshakeStateError); ok {
		if handshakeErr.Code() != int32(pb.HandshakeState_HANDSHAKESTATE_WANT_READ) {
			t.Errorf("Expected WANT_READ, got %v", err)
		}
	} else {
		t.Errorf("Bad type for `error`")
	}

	err = clientTunnel.Handshake()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	err = serverTunnel.Handshake()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// We set the GC tolerance to be very low to make sure any potential zombie pointers are caught.
	debug.SetGCPercent(1)

	for i := 0; i < 1000; i++ {
		data := make([]byte, 32768)
		_, err = rand.Read(data)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		clientTunnel.Write(data)
		serverTunnel.Write(data)

		buf := make([]byte, 32768)
		clientTunnel.Read(buf)
		serverTunnel.Read(buf)

		// Force garbage collection.
		runtime.GC()
		debug.FreeOSMemory()
	}

	clientTunnel.Close()
	serverTunnel.Close()
}

// createEmptyVerifier creates an empty TunnelVerifier.
func createEmptyTunnelVerifier() *api.TunnelVerifier {
	return &api.TunnelVerifier{
		Verifier: &api.TunnelVerifier_EmptyVerifier{
			EmptyVerifier: &api.EmptyVerifier{},
		},
	}
}

// createServerExpiredConfiguration creates the configuration for the server using an expired certificate.
func createServerExpiredConfiguration(t *testing.T) (*api.Configuration, error) {
	certfile, err := bazel.Runfile(certExpiredPath)
	if err != nil {
		t.Errorf("Could not load certificate file %s: %v", certPath, err)
	}
	keyfile, err := bazel.Runfile(keyExpiredPath)
	if err != nil {
		t.Errorf("Could not load private key file %s: %v", keyPath, err)
	}

	return &api.Configuration{
		Impl: api.Implementation_IMPL_OPENSSL1_1_1_OQS,
		Opts: &api.Configuration_Server{
			Server: &api.ServerOptions{
				Opts: &api.ServerOptions_Tls{
					Tls: &api.TLSServerOptions{
						CommonOptions: &api.TLSOptions{
							Kem: []string{
								"kyber1024",
							},
							PeerVerifier: &api.TLSOptions_EmptyVerifier{
								EmptyVerifier: &api.EmptyVerifier{},
							},
							Identity: &api.X509Identity{
								Certificate: &api.Certificate{
									Source: &api.Certificate_Static{
										Static: &api.ASN1DataSource{
											Data: &api.DataSource{
												Specifier: &api.DataSource_Filename{
													Filename: certfile,
												},
											},
											Format: api.ASN1EncodingFormat_ENCODING_FORMAT_PEM,
										},
									},
								},
								PrivateKey: &api.PrivateKey{
									Source: &api.PrivateKey_Static{
										Static: &api.ASN1DataSource{
											Data: &api.DataSource{
												Specifier: &api.DataSource_Filename{
													Filename: keyfile,
												},
											},
											Format: api.ASN1EncodingFormat_ENCODING_FORMAT_PEM,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, nil
}

// createClientExpiredConfiguration creates the configuration for the client using an expired certificate.
func createClientExpiredConfiguration(t *testing.T) (*api.Configuration, error) {
	certfile, err := bazel.Runfile(certExpiredPath)
	if err != nil {
		t.Errorf("Could not load certificate file %s: %v", certPath, err)
	}

	return &api.Configuration{
		Impl: api.Implementation_IMPL_OPENSSL1_1_1_OQS,
		Opts: &api.Configuration_Client{
			Client: &api.ClientOptions{
				Opts: &api.ClientOptions_Tls{
					Tls: &api.TLSClientOptions{
						CommonOptions: &api.TLSOptions{
							Kem: []string{
								"kyber1024",
							},
							PeerVerifier: &api.TLSOptions_X509Verifier{
								X509Verifier: &api.X509Verifier{
									TrustedCas: []*api.Certificate{
										{
											Source: &api.Certificate_Static{
												Static: &api.ASN1DataSource{
													Data: &api.DataSource{
														Specifier: &api.DataSource_Filename{
															Filename: certfile,
														},
													},
													Format: api.ASN1EncodingFormat_ENCODING_FORMAT_PEM,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, nil
}

// createServerExpiredContext creates the server context using an expired certificate.
func createServerExpiredContext(t *testing.T) (*sandwich.Context, error) {
	config, err := createServerExpiredConfiguration(t)
	if err != nil {
		t.Errorf("Failed to create the server configuration: %v", err)
		panic("failed")
	}

	ctx, err := sandwich.NewContext(config)
	if err != nil {
		t.Errorf("Failed to create the server context: %v", err)
		panic("failed")
	}

	return ctx, nil
}

// createClientExpiredContext creates the client context using an expired certificate.
func createClientExpiredContext(t *testing.T) (*sandwich.Context, error) {
	config, err := createClientExpiredConfiguration(t)
	if err != nil {
		t.Errorf("Failed to create the client configuration: %v", err)
		panic("failed")
	}

	ctx, err := sandwich.NewContext(config)
	if err != nil {
		t.Errorf("Failed to create the client context: %v", err)
	}

	return ctx, nil
}

func TestExpiredTunnels(t *testing.T) {
	serverContext, err := createServerExpiredContext(t)
	if err != nil {
		t.Errorf("Failed to create Server context: %v", err)
	}

	clientContext, err := createClientExpiredContext(t)
	if err != nil {
		t.Errorf("Failed to create Client context: %v", err)
	}

	ioInterfaces := createIOs()

	serverTunnel, err := createServerTunnel(t, serverContext, ioInterfaces.server)
	if err != nil {
		t.Errorf("Failed to create the server tunnel: %v", err)
	}

	clientTunnel, err := createClientTunnel(t, clientContext, ioInterfaces.client)
	if err != nil {
		t.Errorf("Failed to create the server tunnel: %v", err)
	}

	err = clientTunnel.Handshake()
	if err == nil {
		t.Errorf("Expected errHanshake not nil, got nil")
	}
	if handshakeErr, ok := err.(*sandwich.HandshakeStateError); ok {
		if handshakeErr.Code() != int32(pb.HandshakeState_HANDSHAKESTATE_WANT_READ) {
			t.Errorf("Expected WANT_READ, got %v", err)
		}
	} else {
		t.Errorf("Bad type for `error`")
	}

	err = serverTunnel.Handshake()
	if err == nil {
		t.Errorf("Expected errHanshake not nil, got nil")
	}
	if handshakeErr, ok := err.(*sandwich.HandshakeStateError); ok {
		if handshakeErr.Code() != int32(pb.HandshakeState_HANDSHAKESTATE_WANT_READ) {
			t.Errorf("Expected WANT_READ, got %v", err)
		}
	} else {
		t.Errorf("Bad type for `error` %v", err)
	}

	err = clientTunnel.Handshake()
	if err == nil {
		t.Errorf("Expected an error, got nil")
	}
	if handshakeErr, ok := err.(*sandwich.HandshakeError); ok {
		if handshakeErr.Code() != int32(pb.HandshakeError_HANDSHAKEERROR_CERTIFICATE_EXPIRED) {
			t.Errorf("Expected CERTIFICATE_EXPIRED, got %v", err)
		}
	} else {
		t.Errorf("Bad type for `error`")
	}
	clientTunnel.Close()
	serverTunnel.Close()
}
