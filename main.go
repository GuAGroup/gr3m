// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"gr3m/client"
	"gr3m/core"
	"gr3m/server"
	"net"
	"time"
)

func main() {
	cfgPath := flag.String("c", "config.json", "path")
	flag.Parse()

	core.LoadConfig(*cfgPath)
	cfg := core.GlobalConfig

	if cfg.Mode == "server" {
		runServer(cfg.ListenAddr)
	} else {
		for {
			fastest := core.GetFastestPeer()
			if fastest == "" {
				time.Sleep(5 * time.Second)
				continue
			}
			fmt.Printf("[GR3M] Connected to %s\n", fastest)
			err := runClient(fastest, cfg.SocksAddr)
			if err != nil {
				time.Sleep(3 * time.Second)
			}
		}
	}
}

func runServer(addr string) {
	ln, _ := net.Listen("tcp", addr)
	for {
		c, _ := ln.Accept()
		go func(conn net.Conn) {
			session, err := core.PerformHandshake(conn, true)
			if err != nil {
				server.TriggerHysteria(conn)
				return
			}
			server.HandleClient(conn, session.EncryptionKey)
		}(c)
	}
}

func runClient(remote, socks string) error {
	conn, err := net.Dial("tcp", remote)
	if err != nil {
		return err
	}
	session, err := core.PerformHandshake(conn, false)
	if err != nil {
		return err
	}

	errChan := make(chan error)
	go client.StartSocks5(socks, conn, session.EncryptionKey, errChan)
	return <-errChan
}
