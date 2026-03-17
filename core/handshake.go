// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package core

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"gr3m/key"
	"net"
)

const ProtocolVersion = "GR3M-v1-SECURE"

type SessionResult struct {
	EncryptionKey []byte
}

func PerformHandshake(conn net.Conn, isServer bool) (*SessionResult, error) {
	priv, err, pub := key.GenPrvKeyAndPublic()
	if err != nil {
		return nil, fmt.Errorf("failed to gen keys: %v", err)
	}

	var theirPub [32]byte

	if isServer {

		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err != nil || n < len(ProtocolVersion)+32 {
			return nil, errors.New("invalid handshake header")
		}

		if string(buf[:len(ProtocolVersion)]) != ProtocolVersion {
			return nil, errors.New("protocol version mismatch")
		}
		copy(theirPub[:], buf[n-32:])

		response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		conn.Write(append([]byte(response), pub[:]...))

	} else {

		request := fmt.Sprintf("GET /stream HTTP/1.1\r\nUpgrade: websocket\r\nHost: gr3m-node\r\n\r\n")

		payload := append([]byte(ProtocolVersion), []byte(request)...)
		conn.Write(append(payload, pub[:]...))

		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err != nil || n < 32 {
			return nil, errors.New("server rejected handshake")
		}

		copy(theirPub[:], buf[n-32:])
	}

	shared, err := key.GenSecretKey(theirPub, priv)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	hasher.Write(shared[:])
	sessionKey := hasher.Sum(nil)

	return &SessionResult{EncryptionKey: sessionKey}, nil
}
