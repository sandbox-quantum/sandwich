package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	// --8<-- [start:go_imports]
	swpb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
	swapi "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"
	sw "github.com/sandbox-quantum/sandwich/go"
	// --8<-- [end:go_imports]
)

// --8<-- [start:go_server_cfg]
func createServerConfiguration(certfile *string, keyfile *string) *swapi.Configuration {
	return &swapi.Configuration{
		Impl: swapi.Implementation_IMPL_OPENSSL1_1_1_OQS,
		Compliance: &swapi.Compliance{
			ClassicalChoice: swapi.ClassicalAlgoChoice_CLASSICAL_ALGORITHMS_ALLOW,
		},
		Opts: &swapi.Configuration_Server{
			Server: &swapi.ServerOptions{
				Opts: &swapi.ServerOptions_Tls{
					Tls: &swapi.TLSServerOptions{
						CommonOptions: &swapi.TLSOptions{
							Kem: []string{
								"kyber768",
								"p256_kyber512",
								"secp256k1",
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

// --8<-- [start:go_io_socket]
type ConnToIOWrapper struct {
	conn io.ReadWriteCloser
}

func (c *ConnToIOWrapper) Read(b []byte, tunnel_state swpb.State) (int, *sw.IOError) {
	n, err := c.conn.Read(b)
	if err != nil {
		return 0, sw.NewIOErrorFromEnum(swpb.IOError_IOERROR_UNKNOWN)
	}
	return n, nil
}

func (c *ConnToIOWrapper) Write(b []byte, tunnel_state swpb.State) (int, *sw.IOError) {
	n, err := c.conn.Write(b)
	if err != nil {
		return 0, sw.NewIOErrorFromEnum(swpb.IOError_IOERROR_UNKNOWN)
	}
	return n, nil
}

func (c *ConnToIOWrapper) Close() {
	c.conn.Close()
}

// --8<-- [end:go_io_socket]

type TunnelConn struct {
	conn   net.Conn
	tunnel *sw.Tunnel
}

func (t *TunnelConn) Close() error {
	t.tunnel.Close()
	return t.conn.Close()
}

func SWAccept(ctx *sw.Context, listener net.Listener) (*TunnelConn, error) {
	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	swio := ConnToIOWrapper{conn: conn}
	// --8<-- [start:go_new_tunnel]
	tunnel, err := sw.NewTunnel(ctx, &swio, &swapi.TunnelVerifier{
		Verifier: &swapi.TunnelVerifier_EmptyVerifier{
			EmptyVerifier: &swapi.EmptyVerifier{},
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

	return &TunnelConn{conn: conn, tunnel: tunnel}, nil
}

func handleTunnel(tunnel *TunnelConn) {
	defer tunnel.Close()
	reader := bufio.NewReader(tunnel.tunnel)
	for {
		bytes, err := reader.ReadBytes(byte('\n'))
		if err != nil {
			if err != io.EOF {
				log.Println("failed to read data, err:", err)
			}
			return
		}
		fmt.Printf("%s", bytes)
		tunnel.tunnel.Write(bytes)
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

	conf := createServerConfiguration(serverCert, serverKey)
	tunnel_ctx, err := sw.NewContext(conf)
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
