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
)

func createClientConfiguration() *swapi.Configuration {
	return &swapi.Configuration{
		Impl: swapi.Implementation_IMPL_OPENSSL1_1_1_OQS,
		Compliance: &swapi.Compliance{
			ClassicalChoice: swapi.ClassicalAlgoChoice_CLASSICAL_ALGORITHMS_ALLOW,
		},
		Opts: &swapi.Configuration_Client{
			Client: &swapi.ClientOptions{
				Opts: &swapi.ClientOptions_Tls{
					Tls: &swapi.TLSClientOptions{
						CommonOptions: &swapi.TLSOptions{
							Kem: []string{
								"kyber768",
								"p256_kyber512",
								"prime256v1",
							},
							PeerVerifier: &swapi.TLSOptions_EmptyVerifier{
								EmptyVerifier: &swapi.EmptyVerifier{},
							},
						},
					},
				},
			},
		},
	}
}

func main() {
	host := flag.String("host", "", "Host to connect to")
	port := flag.Int64("port", 0, "TCP port to connect to")

	flag.Parse()

	if *port == 0 || *host == "" {
		log.Fatalln("Please provide a client host and port!")
	}

	swio, ioerr := sw.IOTCPClient(*host, uint16(*port), true)
	if ioerr != nil {
		fmt.Println("Error connecting to destination:", ioerr)
		return
	}

	sw_lib_ctx := sw.NewSandwich()

	ctx, err := sw.NewTunnelContext(sw_lib_ctx, createClientConfiguration())
	if err != nil {
		fmt.Println("Error create tunnel context:", err)
		return
	}

	tunnel, err := sw.NewTunnel(ctx, swio, &swapi.TunnelConfiguration{
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
