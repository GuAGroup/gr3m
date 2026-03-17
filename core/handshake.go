// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"gr3m/key"
	"net"

	utls "github.com/refraction-networking/utls"
)

const ProtocolVersion = "GR3M-v1-SECURE"

type SessionResult struct {
	EncryptionKey []byte
}

func PerformHandshake(conn net.Conn, isServer bool, expectedPubKey string, staticPriv []byte) (*SessionResult, error) {
	if !isServer {
		config := &utls.Config{ServerName: "google.com", InsecureSkipVerify: true}
		uConn := utls.UClient(conn, config, utls.HelloChrome_Auto)

		if err := uConn.Handshake(); err != nil {
			return nil, err
		}
		return secureExchange(uConn, false, expectedPubKey, nil)
	}

	return secureExchange(conn, true, "", staticPriv)
}

func secureExchange(conn net.Conn, isServer bool, expectedPubKey string, staticPriv []byte) (*SessionResult, error) {
	var priv [32]byte
	var pub [32]byte
	var err error

	if isServer && staticPriv != nil {
		copy(priv[:], staticPriv)
		pub = key.GetPublicFromPrivate(priv)
	} else {
		priv, err, pub = key.GenPrvKeyAndPublic()
		if err != nil {
			return nil, err
		}
	}

	var theirPub [32]byte

	if isServer {
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		if n < len(ProtocolVersion)+32 {
			return nil, errors.New("invalid handshake")
		}
		copy(theirPub[:], buf[n-32:])

		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
		conn.Write(append([]byte(resp), pub[:]...))
	} else {
		req := "GET /stream HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"
		payload := append([]byte(ProtocolVersion), []byte(req)...)
		conn.Write(append(payload, pub[:]...))

		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		if n < 32 {
			return nil, errors.New("short server response")
		}
		copy(theirPub[:], buf[n-32:])

		if expectedPubKey != "" {
			hash := sha256.Sum256(theirPub[:])
			if hex.EncodeToString(hash[:]) != expectedPubKey {
				return nil, errors.New("identity mismatch")
			}
		}
	}

	shared, _ := key.GenSecretKey(theirPub, priv)
	hasher := sha256.New()
	hasher.Write(shared[:])

	return &SessionResult{EncryptionKey: hasher.Sum(nil)}, nil
}
