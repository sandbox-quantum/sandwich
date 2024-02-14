// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	// --8<-- [start:go_imports]
	swproto "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	swapi "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"
	sw "github.com/sandbox-quantum/sandwich/go"
	// --8<-- [end:go_imports]
)

// --8<-- [start:go_server_cfg]
func createServerConfiguration(certfile *string, keyfile *string) *swapi.Configuration {
	return &swapi.Configuration{
		Impl: swapi.Implementation_IMPL_OPENSSL1_1_1_OQS,
		Opts: &swapi.Configuration_Server{
			Server: &swapi.ServerOptions{
				Opts: &swapi.ServerOptions_Tls{
					Tls: &swapi.TLSServerOptions{
						CommonOptions: &swapi.TLSOptions{
							Tls13: &swapi.TLSv13Config{
								Compliance: &swapi.Compliance{
									ClassicalChoice: swapi.ClassicalAlgoChoice_CLASSICAL_ALGORITHMS_ALLOW,
								},
								Ke: []string{
									"kyber768",
									"p256_kyber512",
									"prime256v1",
								},
							},
							Tls12: &swapi.TLSv12Config{
								Ciphersuite: []string{
									"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
									"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
									"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
									"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
									"TLS_RSA_WITH_AES_256_GCM_SHA384",
									"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
									"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
									"TLS_RSA_WITH_AES_128_GCM_SHA256",
								},
							},
							PeerVerifier: &swapi.TLSOptions_EmptyVerifier{
								EmptyVerifier: &swapi.EmptyVerifier{},
							},
							Identity: &swapi.X509Identity{
								Certificate: &swapi.Certificate{
									Source: &swapi.Certificate_Static{
										Static: &swapi.ASN1DataSource{
											Data: &swapi.DataSource{
												Specifier: &swapi.DataSource_Filename{
													Filename: *certfile,
												},
											},
											Format: swapi.ASN1EncodingFormat_ENCODING_FORMAT_PEM,
										},
									},
								},
								PrivateKey: &swapi.PrivateKey{
									Source: &swapi.PrivateKey_Static{
										Static: &swapi.ASN1DataSource{
											Data: &swapi.DataSource{
												Specifier: &swapi.DataSource_Filename{
													Filename: *keyfile,
												},
											},
											Format: swapi.ASN1EncodingFormat_ENCODING_FORMAT_PEM,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// --8<-- [end:go_server_cfg]

// connWrapper wraps a connection.
type connWrapper struct {
	// conn is the connection.
	conn net.Conn
}

// Read implements io.Read.
func (conn *connWrapper) Read(b []byte) (int, error) {
	return conn.conn.Read(b)
}

// Write implements io.Write.
func (conn *connWrapper) Write(b []byte) (int, error) {
	return conn.conn.Write(b)
}

// SetState implements sw.TunnelIO.
func (conn *connWrapper) SetState(tunnel_state swproto.State) {}

func SWAccept(ctx *sw.TunnelContext, listener net.Listener) (*sw.Tunnel, error) {
	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	// --8<-- [start:go_new_tunnel]
	tunnel, err := sw.NewTunnel(ctx, &connWrapper{conn: conn}, &swapi.TunnelConfiguration{
		Verifier: &swapi.TunnelVerifier{
			Verifier: &swapi.TunnelVerifier_EmptyVerifier{
				EmptyVerifier: &swapi.EmptyVerifier{},
			},
		},
	})
	// --8<-- [end:go_new_tunnel]
	if err != nil {
		return nil, err
	}

	err = tunnel.Handshake()
	if err != nil {
		return nil, err
	}

	return tunnel, nil
}

func handleTunnel(tunnel *sw.Tunnel) {
	defer tunnel.Close()
	reader := bufio.NewReader(tunnel)
	for {
		bytes, err := reader.ReadBytes(byte('\n'))
		if err != nil {
			if err != io.EOF {
				log.Println("failed to read data, err:", err)
			}
			return
		}
		fmt.Printf("%s", bytes)
		tunnel.Write(bytes)
	}
}

func main() {
	serverCert := flag.String("server_cert", "", "Server public certificate")
	serverKey := flag.String("server_key", "", "Server private key")
	port := flag.String("port", "", "TCP listening port")
	host := flag.String("host", "127.0.0.1", "TCP listening host")

	flag.Parse()

	if *serverCert == "" || *serverKey == "" {
		log.Fatalln("Please provide a server certificate and key")
	}

	if *port == "" {
		log.Fatalln("Please provide a server port")
	}

	sw_lib_ctx := sw.NewSandwich()

	conf := createServerConfiguration(serverCert, serverKey)
	tunnel_ctx, err := sw.NewTunnelContext(sw_lib_ctx, conf)
	if err != nil {
		log.Fatalln(err)
	}

	listen, err := net.Listen("tcp", *host+":"+*port)
	if err != nil {
		log.Fatalln(err)
	}
	defer listen.Close()
	for {
		conn, err := SWAccept(tunnel_ctx, listen)
		if err != nil {
			log.Println(err)
			continue
		}
		go handleTunnel(conn)
	}
}
