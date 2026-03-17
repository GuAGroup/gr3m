package server

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"gr3m/protocol"
)

var (
	activeStreams = make(map[uint32]net.Conn)
	streamsMu     sync.RWMutex
)

func HandleClient(conn net.Conn, encKey []byte) {
	defer conn.Close()

	for {
		headBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, headBuf); err != nil {
			return
		}
		frameLen := binary.BigEndian.Uint32(headBuf)

		if frameLen > 2*1024*1024 {
			TriggerHysteria(conn)
			return
		}

		cipherFrame := make([]byte, frameLen)
		if _, err := io.ReadFull(conn, cipherFrame); err != nil {
			return
		}

		streamID, data, err := protocol.Unpack(cipherFrame, encKey)
		if err != nil {
			TriggerHysteria(conn)
			return
		}

		handleStreamData(conn, streamID, data, encKey)
	}
}

func handleStreamData(mainConn net.Conn, id uint32, data []byte, key []byte) {
	streamsMu.Lock()
	remote, exists := activeStreams[id]
	streamsMu.Unlock()

	if !exists {
		target := "google.com:80"
		newRemote, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			return
		}
		remote = newRemote
		streamsMu.Lock()
		activeStreams[id] = remote
		streamsMu.Unlock()

		go func(sID uint32, r net.Conn) {
			buf := make([]byte, 32*1024)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					packet, _ := protocol.Pack(sID, buf[:n], key)
					header := make([]byte, 4)
					binary.BigEndian.PutUint32(header, uint32(len(packet)))
					mainConn.Write(header)
					mainConn.Write(packet)
				}
				if err != nil {
					break
				}
			}
			r.Close()
		}(id, remote)
	}

	remote.Write(data)
}

func TriggerHysteria(conn net.Conn) {
	target, err := net.DialTimeout("tcp", "wikipedia.org:80", 5*time.Second)
	if err != nil {
		conn.Close()
		return
	}
	go io.Copy(target, conn)
	go io.Copy(conn, target)
}
