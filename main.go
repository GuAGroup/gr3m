// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
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
		log.Fatalf("[FATAL] Ошибка конфига: %v", err)
	}

	cfg := core.GlobalConfig
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Mode == "server" {
		runServer(ctx, &cfg)
	} else {
		runClientLoop(ctx, &cfg)
	}

	<-ctx.Done()
	fmt.Println("\n[SYSTEM] Завершение работы...")
}

func runServer(ctx context.Context, cfg *core.Config) {
	privKey, _ := hex.DecodeString(cfg.PrivateKey)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("[SERVER] Не удалось занять порт: %v", err)
	}

	fmt.Printf("[TIGER-SERVER] Рычит на %s\n", cfg.ListenAddr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}

			go func(c net.Conn) {
				fmt.Printf("[SERVER] Входящий: %s\n", c.RemoteAddr())
				session, err := core.PerformHandshake(c, true, "", privKey)
				if err != nil {
					fmt.Printf("[SERVER] Ошибка хендшейка: %v\n", err)
					server.TriggerHysteria(c)
					return
				}
				fmt.Printf("[SERVER] Туннель готов для %s\n", c.RemoteAddr())
				server.HandleClient(c, session.EncryptionKey)
			}(conn)
		}
	}()
}

func runClientLoop(ctx context.Context, cfg *core.Config) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			peer := core.GetFastestPeer()
			if peer == nil {
				fmt.Println("[CLIENT] Список серверов пуст. Жду...")
				time.Sleep(5 * time.Second)
				continue
			}

			fmt.Printf("[CLIENT] Прыжок на %s...\n", peer.Addr)
			conn, err := net.DialTimeout("tcp", peer.Addr, 10*time.Second)
			if err != nil {
				fmt.Printf("[CLIENT] Ошибка сети: %v\n", err)
				time.Sleep(5 * time.Second)
				continue
			}

			session, err := core.PerformHandshake(conn, false, peer.PubKey, nil)
			if err != nil {
				fmt.Printf("[CLIENT] Ошибка защиты: %v\n", err)
				conn.Close()
				time.Sleep(5 * time.Second)
				continue
			}

			fmt.Printf("[CLIENT] Туннель пробит! Ключ сессии: %x\n", session.EncryptionKey[:4])

			errChan := make(chan error, 1)

			client.StartSocks5(cfg.SocksAddr, conn, session.EncryptionKey, errChan)

			conn.Close()
			fmt.Println("[CLIENT] Переподключение через 3 секунды...")
			time.Sleep(3 * time.Second)
		}
	}
}
