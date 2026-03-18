// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtaci/smux"
)

func HandleClient(conn net.Conn, key []byte) {
	session, err := smux.Server(conn, nil)
	if err != nil {
		conn.Close()
		return
	}

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			break
		}
		go handleTargetStream(stream)
	}
}

func handleTargetStream(s *smux.Stream) {
	defer s.Close()

	header := make([]byte, 1)
	if _, err := s.Read(header); err != nil {
		return
	}
	addrLen := int(header[0])
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(s, addrBuf); err != nil {
		return
	}
	targetAddr := string(addrBuf)

	fmt.Printf("[SERVER] Соединение с: %s\n", targetAddr)
	remote, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(remote, s)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(s, remote)
		errChan <- err
	}()

	<-errChan
}

func TriggerHysteria(conn net.Conn) {
	defer conn.Close()
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nServer: nginx\r\nConnection: close\r\n\r\n")
}
