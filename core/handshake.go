package core

import (
	"fmt"
	"net"
	"time"

	"gr3m/key"
)

type SessionResult struct {
	EncryptionKey []byte
	IntegrityKey  []byte
}

func PerformHandshake(conn net.Conn, isServer bool) (*SessionResult, error) {
	conn.SetDeadline(time.Now().Add(7 * time.Second))
	defer conn.SetDeadline(time.Time{})

	myPriv, err, myPub := key.GenPrvKeyAndPublic()
	if err != nil {
		return nil, err
	}

	var theirPub [32]byte

	if isServer {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil || n < 32 {
			return nil, fmt.Errorf("invalid handshake request")
		}
		copy(theirPub[:], buf[n-32:])

		fakeHTTP := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: gr3m-v1\r\n\r\n"
		conn.Write([]byte(fakeHTTP))
		conn.Write(myPub[:])
	} else {
		fakeReq := "GET /chat/v1 HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		conn.Write([]byte(fakeReq))
		conn.Write(myPub[:])

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil || n < 32 {
			return nil, fmt.Errorf("invalid handshake response")
		}
		copy(theirPub[:], buf[n-32:])
	}

	shared, err := key.GenSecretKey(theirPub, myPriv)
	if err != nil {
		return nil, err
	}

	enc, mac, err := key.SetupSessionKeys(shared[:])
	if err != nil {
		return nil, err
	}

	return &SessionResult{EncryptionKey: enc, IntegrityKey: mac}, nil
}
