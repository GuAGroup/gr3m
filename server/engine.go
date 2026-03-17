// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"encoding/binary"
	"fmt"
	"gr3m/protocol"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	activeStreams = make(map[uint32]net.Conn)
	streamsMu     sync.RWMutex
)

func HandleClient(conn net.Conn, encKey []byte) {
	defer conn.Close()
	state := &protocol.SessionState{Key: encKey}

	for {
		headBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, headBuf); err != nil {
			return
		}
		frameLen := binary.BigEndian.Uint32(headBuf)

		cipherFrame := make([]byte, frameLen)
		if _, err := io.ReadFull(conn, cipherFrame); err != nil {
			return
		}

		streamID, data, err := state.Unpack(cipherFrame)
		if err != nil {
			TriggerHysteria(conn)
			return
		}

		handleStreamData(conn, streamID, data, state)
	}
}

func handleStreamData(mainConn net.Conn, id uint32, data []byte, state *protocol.SessionState) {
	streamsMu.Lock()
	remote, exists := activeStreams[id]
	streamsMu.Unlock()

	if !exists {
		target, err := parseSocksAddr(data)
		if err != nil {
			return
		}

		newRemote, err := net.DialTimeout("tcp", target, 7*time.Second)
		if err != nil {
			return
		}

		streamsMu.Lock()
		activeStreams[id] = newRemote
		streamsMu.Unlock()

		success := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		p, _ := state.Pack(id, success)
		sendRaw(mainConn, p)

		go func(sID uint32, r net.Conn, st *protocol.SessionState) {
			defer r.Close()
			buf := make([]byte, 32*1024)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					pk, _ := st.Pack(sID, buf[:n])
					if sendRaw(mainConn, pk) != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
			streamsMu.Lock()
			delete(activeStreams, sID)
			streamsMu.Unlock()
		}(id, newRemote, state)
		return
	}
	remote.Write(data)
}

func parseSocksAddr(data []byte) (string, error) {
	if len(data) < 7 {
		return "", fmt.Errorf("short")
	}
	var host string
	var port int
	switch data[3] {
	case 0x01:
		host = net.IP(data[4:8]).String()
		port = int(binary.BigEndian.Uint16(data[8:10]))
	case 0x03:
		l := int(data[4])
		host = string(data[5 : 5+l])
		port = int(binary.BigEndian.Uint16(data[5+l : 7+l]))
	default:
		return "", fmt.Errorf("unsupported")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func sendRaw(c net.Conn, p []byte) error {
	h := make([]byte, 4)
	binary.BigEndian.PutUint32(h, uint32(len(p)))
	c.Write(h)
	_, err := c.Write(p)
	return err
}

func TriggerHysteria(c net.Conn) {
	target, _ := net.Dial("tcp", "wikipedia.org:80")
	if target != nil {
		go io.Copy(target, c)
		go io.Copy(c, target)
	}
}
