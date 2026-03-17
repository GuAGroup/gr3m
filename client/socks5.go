// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package client

import (
	"encoding/binary"
	"gr3m/protocol"
	"net"
	"sync/atomic"
)

func StartSocks5(localAddr string, tunnel net.Conn, key []byte, errChan chan error) {
	ln, _ := net.Listen("tcp", localAddr)
	state := &protocol.SessionState{Key: key}
	var streamCounter uint32

	for {
		bConn, err := ln.Accept()
		if err != nil {
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			id := atomic.AddUint32(&streamCounter, 1)

			buf := make([]byte, 1024)
			c.Read(buf)
			c.Write([]byte{0x05, 0x00})

			n, err := c.Read(buf)
			if err != nil {
				return
			}

			p, _ := state.Pack(id, buf[:n])
			if err := sendRaw(tunnel, p); err != nil {
				errChan <- err
				return
			}

			pipe(c, id, tunnel, state, errChan)
		}(bConn)
	}
}

func pipe(b net.Conn, id uint32, t net.Conn, s *protocol.SessionState, errChan chan error) {
	buf := make([]byte, 32*1024)
	for {
		n, err := b.Read(buf)
		if n > 0 {
			p, _ := s.Pack(id, buf[:n])
			if err := sendRaw(t, p); err != nil {
				errChan <- err
				return
			}
		}
		if err != nil {
			break
		}
	}
}

func sendRaw(conn net.Conn, packet []byte) error {
	h := make([]byte, 4)
	binary.BigEndian.PutUint32(h, uint32(len(packet)))
	_, err := conn.Write(h)
	if err != nil {
		return err
	}
	_, err = conn.Write(packet)
	return err
}
