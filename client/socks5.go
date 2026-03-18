// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"fmt"
	"net"

	"github.com/armon/go-socks5"
	"github.com/xtaci/smux"
)

func StartSocks5(localAddr string, tunnel net.Conn, key []byte, errChan chan error) {
	session, err := smux.Client(tunnel, nil)
	if err != nil {
		errChan <- err
		return
	}

	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			stream, err := session.OpenStream()
			if err != nil {
				return nil, err
			}

			addrBytes := []byte(addr)
			header := []byte{byte(len(addrBytes))}
			stream.Write(append(header, addrBytes...))

			fmt.Printf("[SOCKS5] Проброс на: %s\n", addr)
			return stream, nil
		},
	}

	server, _ := socks5.New(conf)
	if err := server.ListenAndServe("tcp", localAddr); err != nil {
		errChan <- err
	}
}
