// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package sandwich_test

import (
	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	"github.com/sandbox-quantum/sandwich/go"
	"fmt"
	"github.com/bazelbuild/rules_go/go/tools/bazel"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	api "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"
)

var testCertPattern = "testdata/%s.cert.pem"

var (
	pingMsg         = [...]byte{'P', 'I', 'N', 'G'}
	pongMsg         = [...]byte{'P', 'O', 'N', 'G'}
	certPath string = "testdata/localhost.cert.pem"
	keyPath  string = "testdata/localhost.key.pem"
)

// bufIO implements sandwich.IO, using a TX buffer and a
// remote peer.
type serverIO struct {
	io *net.Conn
}

// newBufIO Creates a new buffer IO.
func newServerIO() *serverIO {
	return new(serverIO)
}

// Reads implements the sandwich.IO interface for bufIO.
func (io *serverIO) Read(b []byte, tunnel_state pb.State) (int, *sandwich.IOError) {
	(*(io.io)).SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	bytes_read, err := (*(io.io)).Read(b)
	if bytes_read == 0 {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_WOULD_BLOCK)
	}
	if err != nil && err.(*net.OpError).Err == os.ErrDeadlineExceeded {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_WOULD_BLOCK)
	} else if err != nil {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_UNKNOWN)
	}
	return bytes_read, nil
}

// Write implements the sandwich.IO interface for bufIO.
func (io *serverIO) Write(b []byte, tunnel_state pb.State) (int, *sandwich.IOError) {
	(*(io.io)).SetWriteDeadline(time.Now().Add(1 * time.Millisecond))
	bytes_written, err := (*(io.io)).Write(b)
	if bytes_written == 0 {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_WOULD_BLOCK)
	}
	if err != nil && err.(*net.OpError).Err == os.ErrDeadlineExceeded {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_WOULD_BLOCK)
	}
	if err != nil {
		return 0, sandwich.NewIOErrorFromEnum(pb.IOError_IOERROR_UNKNOWN)
	}
	return bytes_written, nil
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
						},
					},
				},
			},
		},
	}, nil
}

// createServerContext creates the server context.
func createServerContext(t *testing.T, sw *sandwich.Sandwich) (*sandwich.TunnelContext, error) {
	config, err := createServerConfiguration(t)
	if err != nil {
		t.Errorf("Failed to create the server configuration: %v", err)
		panic("failed")
	}

	ctx, err := sandwich.NewTunnelContext(sw, config)
	if err != nil {
		t.Errorf("Failed to create the server context: %v", err)
		panic("failed")
	}

	return ctx, nil
}

// createClientContext creates the client context.
func createClientContext(t *testing.T, sw *sandwich.Sandwich) (*sandwich.TunnelContext, error) {
	config, err := createClientConfiguration(t)
	if err != nil {
		t.Errorf("Failed to create the client configuration: %v", err)
		panic("failed")
	}

	ctx, err := sandwich.NewTunnelContext(sw, config)
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
	hostname := "127.0.0.1"
	listener, err := net.Listen("tcp", hostname+":0")
	if err != nil {
		fmt.Println("Error listening:", err)
	}
	defer listener.Close()

	// Extracts port number from listener
	port := strings.Split(listener.Addr().String(), ":")[1]
	listener_port, _ := strconv.ParseUint(port, 10, 64)

	// Connects to kernel assigned port
	client, _ := sandwich.IOTCPClient(hostname, uint16(listener_port), true)
	server := newServerIO()
	conn, err := listener.Accept()
	if err != nil {
		fmt.Println("Error accepting:", err)
	}
	server.io = &conn
	return ioInts{
		client: client,
		server: server,
	}
}

// createServerTunnel creates the tunnel for the server.
func createServerTunnel(t *testing.T, context *sandwich.TunnelContext, io sandwich.IO) (*sandwich.Tunnel, error) {
	tun, err := sandwich.NewTunnel(context, io, createTunnelConfigurationWithEmptyTunnelVerifier())
	if err != nil {
		t.Errorf("Failed to create the server's tunnel: %v", err)
	}

	return tun, nil
}

// createClientTunnel creates the tunnel for the client.
func createClientTunnel(t *testing.T, context *sandwich.TunnelContext, io sandwich.IO) (*sandwich.Tunnel, error) {
	tun, err := sandwich.NewTunnel(context, io, createTunnelConfigurationWithEmptyTunnelVerifier())
	if err != nil {
		t.Errorf("Failed to create the client's tunnel: %v", err)
	}

	return tun, nil
}

// createTunnelConfigurationWithEmptyTunnelVerifier creates a tunnel configuration with an empty TunnelVerifier.
func createTunnelConfigurationWithEmptyTunnelVerifier() *api.TunnelConfiguration {
	return &api.TunnelConfiguration{
		Verifier: &api.TunnelVerifier{
			Verifier: &api.TunnelVerifier_EmptyVerifier{
				EmptyVerifier: &api.EmptyVerifier{},
			},
		},
	}
}

func clientRoutine(t *testing.T, wg *sync.WaitGroup, clientTunnel *sandwich.Tunnel, recvMsg [4]byte, sendMsg [4]byte) {
	var buf [4]byte
	err := clientTunnel.Handshake()
	n := 0
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	n, err = clientTunnel.Write(pingMsg[:])
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if n != len(pingMsg) {
		t.Errorf("Expected %v bytes sent, got %v", len(pingMsg), n)
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
	wg.Done()
}

func serverRoutine(t *testing.T, wg *sync.WaitGroup, serverTunnel *sandwich.Tunnel, recvMsg [4]byte, sendMsg [4]byte) {
	var buf [4]byte
	n := 0
	err := serverTunnel.Handshake()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	n, err = serverTunnel.Read(buf[:])
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if n != len(recvMsg) {
		t.Errorf("Expected %v bytes read, got %v", len(recvMsg), n)
	}
	if buf != recvMsg {
		t.Errorf("Expected %v, got %v", recvMsg, buf)
	}

	n, err = serverTunnel.Write(sendMsg[:])
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if n != len(sendMsg) {
		t.Errorf("Expected %v bytes sent, got %v", len(sendMsg), n)
	}

	serverTunnel.Close()
	wg.Done()
}

func TestTunnels(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)
	sw := sandwich.NewSandwich()
	serverContext, err := createServerContext(t, sw)
	if err != nil {
		t.Errorf("Failed to create Server context: %v", err)
	}

	clientContext, err := createClientContext(t, sw)
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
	go func() {
		serverRoutine(t, &wg, serverTunnel, pingMsg, pongMsg)
	}()
	go func() {
		clientRoutine(t, &wg, clientTunnel, pongMsg, pingMsg)
	}()
	wg.Wait()
}
