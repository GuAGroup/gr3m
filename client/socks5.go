package client

import (
	"encoding/binary"
	"net"
	"sync/atomic"

	"gr3m/protocol"
)

var lastStreamID uint32

func StartSocks5(localAddr string, tunnel net.Conn, key []byte, errChan chan error) {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		errChan <- err
		return
	}
	defer ln.Close()

	for {
		bConn, err := ln.Accept()
		if err != nil {
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			id := atomic.AddUint32(&lastStreamID, 1)

			buf := make([]byte, 1024)
			c.Read(buf)
			c.Write([]byte{0x05, 0x00})

			n, err := c.Read(buf)
			if err != nil {
				return
			}

			p, _ := protocol.Pack(id, buf[:n], key)
			if err := sendRaw(tunnel, p); err != nil {
				errChan <- err
				return
			}

			pipe(c, id, tunnel, key, errChan)
		}(bConn)
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

func pipe(b net.Conn, id uint32, t net.Conn, key []byte, errChan chan error) {
	buf := make([]byte, 32*1024)
	for {
		n, err := b.Read(buf)
		if n > 0 {
			p, _ := protocol.Pack(id, buf[:n], key)
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
