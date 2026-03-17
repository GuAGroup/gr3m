// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package core

import (
	"crypto/sha256"
	"fmt"
	"gr3m/key"
	"net"
)

type SessionResult struct {
	EncryptionKey []byte
}

func PerformHandshake(conn net.Conn, isServer bool) (*SessionResult, error) {

	priv, err, pub := key.GenPrvKeyAndPublic()
	if err != nil {
		return nil, err
	}

	var theirPub [32]byte
	protoHeader := []byte("GR3M-V1-SECURE")

	if isServer {
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)

		if n < len(protoHeader)+32 {
			return nil, fmt.Errorf("incompatible protocol")
		}
		copy(theirPub[:], buf[n-32:])

		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		conn.Write(append([]byte(resp), pub[:]...))
	} else {

		req := "GET /stream HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"
		conn.Write(append([]byte(req), pub[:]...))

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		copy(theirPub[:], buf[n-32:])
	}

	shared, _ := key.GenSecretKey(theirPub, priv)

	finalKey := sha256.Sum256(shared[:])

	return &SessionResult{EncryptionKey: finalKey[:]}, nil
}
