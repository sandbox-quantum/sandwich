// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	swapi "github.com/sandbox-quantum/sandwich/go/proto/sandwich/api/v1"
	sw "github.com/sandbox-quantum/sandwich/go"
	swio "github.com/sandbox-quantum/sandwich/go/io"
	swtunnel "github.com/sandbox-quantum/sandwich/go/tunnel"
)

func createClientConfiguration(cert *string, tls_version *string) *swapi.Configuration {
	EmptyVerifier := &swapi.TLSOptions_EmptyVerifier{
		EmptyVerifier: &swapi.EmptyVerifier{},
	}

	x509_verifier := &swapi.TLSOptions_X509Verifier{
		X509Verifier: &swapi.X509Verifier{
			TrustedCas: []*swapi.Certificate{
				{
					Source: &swapi.Certificate_Static{
						Static: &swapi.ASN1DataSource{
							Data: &swapi.DataSource{
								Specifier: &swapi.DataSource_Filename{
									Filename: *cert,
								},
							},
							Format: swapi.ASN1EncodingFormat_ENCODING_FORMAT_PEM,
						},
					},
				},
			},
		},
	}

	config := &swapi.Configuration{
		Impl: swapi.Implementation_IMPL_OPENSSL1_1_1_OQS,
		Opts: &swapi.Configuration_Client{
			Client: &swapi.ClientOptions{
				Opts: &swapi.ClientOptions_Tls{
					Tls: &swapi.TLSClientOptions{
						CommonOptions: &swapi.TLSOptions{
							PeerVerifier: &swapi.TLSOptions_EmptyVerifier{
								EmptyVerifier: &swapi.EmptyVerifier{},
							},
						},
					},
				},
			},
		},
	}

	tls13config := &swapi.TLSv13Config{
		Compliance: &swapi.Compliance{
			ClassicalChoice: swapi.ClassicalAlgoChoice_CLASSICAL_ALGORITHMS_ALLOW,
		},
		Ke: []string{
			"kyber768",
			"p256_kyber512",
			"prime256v1",
		},
	}

	tls12config := &swapi.TLSv12Config{
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
	}

	switch *tls_version {
	case "tls12":
		config.GetClient().GetTls().CommonOptions.Tls12 = tls12config
	case "tls13":
		config.GetClient().GetTls().CommonOptions.Tls13 = tls13config
	default:
		log.Fatalln("TLS version is not supported")
	}

	if len(*cert) == 0 {
		config.GetClient().GetTls().CommonOptions.PeerVerifier = EmptyVerifier
	} else {
		config.GetClient().GetTls().CommonOptions.PeerVerifier = x509_verifier
	}

	return config
}

func main() {
	host := flag.String("host", "", "Host to connect to")
	port := flag.Int64("port", 0, "TCP port to connect to")
	tls_version := flag.String("tls_version", "", "TLS version: --tls_version tls13 or tls12")
	cert := flag.String("server_cert", "", "Server certificates")

	flag.Parse()

	if *port == 0 || *host == "" {
		log.Fatalln("Please provide a client host and port!")
	}

	if *tls_version == "" {
		log.Fatalln("Please provide a TLS protocol version, e.g --tls_version tls13 or tls12")
	}

	swio, ioerr := swio.IOTCPClient(*host, uint16(*port))
	if ioerr != nil {
		log.Fatalln("Error connecting to destination:", ioerr)
		return
	}

	sw_lib_ctx := sw.NewSandwich()

	ctx, err := swtunnel.NewTunnelContext(sw_lib_ctx, createClientConfiguration(cert, tls_version))
	if err != nil {
		log.Fatalln("Error create tunnel context:", err)
		return
	}

	tunnel, err := swtunnel.NewTunnelWithReadWriter(ctx, swio, &swapi.TunnelConfiguration{
		Verifier: &swapi.TunnelVerifier{
			Verifier: &swapi.TunnelVerifier_EmptyVerifier{
				EmptyVerifier: &swapi.EmptyVerifier{},
			},
		},
	})
	if err != nil {
		log.Fatalln(err)
	}

	err = tunnel.Handshake()
	if err != nil {
		log.Fatalln(err)
	}

	errChannel := make(chan error)

	// Copy data from stdin to destination using io.Copy
	go func() {
		_, err := io.Copy(tunnel, os.Stdin)
		errChannel <- err
	}()

	// Copy data from source to stdout using io.Copy
	go func() {
		_, err := io.Copy(os.Stdout, tunnel)
		errChannel <- err
	}()

	// Handle Ctrl+C signal to gracefully close the connection
	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-interruptChannel
		os.Exit(0)
	}()

	// Wait for the data copying goroutine to finish
	err = <-errChannel
	if err != nil && err != io.EOF {
		fmt.Println("Error:", err)
	}
}
