// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package client

import (
	"encoding/binary"
	"gr3m/protocol"
	"io"
	"net"
)

func SendRaw(conn net.Conn, key []byte, data []byte) error {
	state := &protocol.SessionState{Key: key}
	packet, err := state.Pack(0, data)
	if err != nil {
		return err
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(packet)))
	conn.Write(header)
	_, err = conn.Write(packet)
	return err
}

func SendFile(stream io.Reader, conn net.Conn, key []byte) error {
	state := &protocol.SessionState{Key: key}
	buf := make([]byte, 15000)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			p, _ := state.Pack(1, buf[:n])
			h := make([]byte, 4)
			binary.BigEndian.PutUint32(h, uint32(len(p)))
			conn.Write(h)
			conn.Write(p)
		}
		if err != nil {
			break
		}
	}
	return nil
}
