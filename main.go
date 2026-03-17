// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gr3m/client"
	"gr3m/core"
	"gr3m/server"
)

func main() {
	configPath := flag.String("c", "config.json", "path to config file")
	flag.Parse()

	if err := core.LoadConfig(*configPath); err != nil {
		log.Fatal(err)
	}

	cfg := core.GlobalConfig

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Mode == "server" {
		var privKey []byte
		if cfg.PrivateKey != "" {
			var err error
			privKey, err = hex.DecodeString(cfg.PrivateKey)
			if err != nil {
				log.Fatal("invalid private key hex")
			}
		}
		go runServer(cfg.ListenAddr, privKey)
	} else {
		go runClientLoop(ctx, &cfg)
	}

	<-ctx.Done()
}

func runServer(addr string, privKey []byte) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}

		go func(c net.Conn) {
			session, err := core.PerformHandshake(c, true, "", privKey)
			if err != nil {
				server.TriggerHysteria(c)
				return
			}
			server.HandleClient(c, session.EncryptionKey)
		}(conn)
	}
}

func runClientLoop(ctx context.Context, cfg *core.Config) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			peer := core.GetFastestPeer()
			if peer == nil {
				time.Sleep(5 * time.Second)
				continue
			}

			err := startTunnel(peer, cfg.SocksAddr)
			if err != nil {
				time.Sleep(2 * time.Second)
			}
		}
	}
}

func startTunnel(peer *core.Peer, socks string) error {
	conn, err := net.DialTimeout("tcp", peer.Addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	session, err := core.PerformHandshake(conn, false, peer.PubKey, nil)
	if err != nil {
		return err
	}

	errChan := make(chan error, 1)
	go client.StartSocks5(socks, conn, session.EncryptionKey, errChan)

	return <-errChan
}
