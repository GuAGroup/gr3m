package client

import (
	"encoding/binary"
	"gr3m/protocol"
	"io"
	"net"
)

func SendRaw(conn net.Conn, key []byte, data []byte) error {
	packet, err := protocol.Pack(0, data, key)
	if err != nil {
		return err
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(packet)))

	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err = conn.Write(packet)
	return err
}

func SendFile(stream io.Reader, conn net.Conn, key []byte) error {
	buf := make([]byte, 15000)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			packet, err := protocol.Pack(1, buf[:n], key)
			if err != nil {
				return err
			}
			header := make([]byte, 4)
			binary.BigEndian.PutUint32(header, uint32(len(packet)))
			conn.Write(header)
			conn.Write(packet)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}
