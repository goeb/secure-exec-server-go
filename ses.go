/*
 * Copyright (C) 2025 Frederic Hoerni
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
)

var usage_text string = `
usage: ses TCP-PORT CERTIFICATE ...

Start a TCP server where clients can submit their scripts, that get
authenticated and executed.

Arguments:
  CERTIFICATE  X509 certificate whose public key is used for authentication.
               It must be in PEM encoding.
               It must carry the x509v3 extension KeyUsage 'digitalSignature'.
               If several certificates are specified, the authentication
               will succeed if at least 1 certificate verifies the signature
  TCP-PORT     Listening port
`

func usage() {
	fmt.Print(usage_text)
	os.Exit(1)
}

func INFO(format string, vaargs ...interface{}) {
	fmt.Printf(format, vaargs...)
	fmt.Printf("\n")
}

func FATAL(format string, vaargs ...interface{}) {
	fmt.Printf(format, vaargs...)
	fmt.Printf("\n")
	os.Exit(1)
}


func main() {
	args := os.Args[1:]
	if len(args) < 2 {
		usage()
	}

	port64, err := strconv.ParseInt(args[0], 10, 16)
	if err != nil {
		FATAL("Invalid argument TCP-PORT: %v", err)
	}
	var port uint16 = uint16(port64)

	var certificates []string = args[1:]
	pubkeys := make([]publicKey, 0)

	for _, certFilename := range certificates {
		pubkey, err := loadPublicKey(certFilename)
		if err != nil {
			INFO("Cannot load certificate '%v': %v", certFilename, err)
		}
		if len(pubkey.filename) == 0 {
			// This certificate should be ignored (bad key usage)
			continue
		}
		pubkeys = append(pubkeys, pubkey)
	}
	if len(pubkeys) == 0 {
		FATAL("No valid public key found")
	}

	// Create a listening socket
	var listener net.Listener
	var err2 error
	listener, err2 = net.Listen("tcp", fmt.Sprintf(":%v", port))
	if err2 != nil {
		FATAL("Error listening: %v", err2)
	}
	defer listener.Close()

	mainloop(listener, pubkeys)
}

func mainloop(listener net.Listener, pubkeys []publicKey) {
	var clientIdentifier uint32 = 0
	for {
		conn, err := listener.Accept()
		if err != nil {
			INFO("Error accepting conn:", err)
			continue
		}
		go handleConnection(conn, clientIdentifier, pubkeys)
		clientIdentifier ++
	}
}

/*
 * Receive a script from a client, authenticate and execute
 *
 * When the connection is closed and "shutdown\n" has been received
 * then it triggers the shutdown of the server.
 */
func handleConnection(conn net.Conn, clientIdentifier uint32, pubkeys []publicKey) {
	INFO("%v: new client connected", clientIdentifier)
	defer conn.Close()

	var bytesReceived []byte
	for {
		buf := make([]byte, 10)
		n, err := conn.Read(buf)
		if err == io.EOF {
			// Concatenate with bytes previously received
			break
		} else if err != nil {
			INFO("%v: read error: %v", clientIdentifier, err)
			return
		}
		bytesReceived = append(bytesReceived, buf[:n]...)
		//INFO("%v: got chunk: %s", clientIdentifier, buf)
	}
	//INFO("%v: recv: %v", clientIdentifier, string(bytesReceived))
	INFO("%v: number of bytes received: %v", clientIdentifier, len(bytesReceived))
	if len(bytesReceived) == 0 {
		// No byte received
	} else if string(bytesReceived) == "shutdown\n" {
		INFO("%v: shutdown requested", clientIdentifier);
		os.Exit(0);
	} else {
		filename, err := authenticateScript(bytesReceived, pubkeys)
		if err != nil {
			INFO("%v: authentication FAILED: %s", clientIdentifier, err);
		} else {
			INFO("%v: authentication OK by %v", clientIdentifier, filename);
			// start the script
			executeScript(bytesReceived, clientIdentifier)
		}
	}
}

/*
 * Start a bash process that will execute the script
 *
 * The script will be sent to the child's stdin, in a separate callback.
 * The output of the process (stdout and stderr) are merged into the server's stdout.
 */
func executeScript(script []byte, clientIdentifier uint32) () {
	var err error
	 // Prefix all output lines of the bash script with the client identifier
	commandWithLabel := fmt.Sprintf("bash 2>&1 | sed --unbuffered -e 's/^/%v: output: /'", clientIdentifier);
	command := exec.Command("bash", "-o", "pipefail", "-c", commandWithLabel);
	stdin, err := command.StdinPipe()
	if err != nil {
		INFO("Cannot get StdinPipe: %v", err)
		return
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		INFO("Cannot get StdoutPipe: %v", err)
		return
	}

	err = command.Start()
	if err != nil {
		INFO("Cannot start subprocess: %v", err)
		return
	}

	pid := command.Process.Pid
	INFO("%d: bash script started (pid=%d)", clientIdentifier, pid);
	stdin.Write(script)
	stdin.Close()

	// Collect and print the process' stdout
	buf := make([]byte, 10)
	for {
		n, err := stdout.Read(buf)
		if n > 0 {
			fmt.Printf("%s", buf[:n])
		}
		if err == io.EOF {
			break
		}
	}

	err = command.Wait()
	if err != nil {
		INFO("%d: child terminated (pid=%d) error: %s", clientIdentifier, pid, err);
	} else {
		INFO("%d: child terminated (pid=%d) ok", clientIdentifier, pid);
	}
}
