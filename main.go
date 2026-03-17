// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
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

	configPath := flag.String("c", "config.json", "Путь к файлу конфигурации")
	flag.Parse()

	log.Println("[GR3M] Инициализация протокола...")

	if err := core.LoadConfig(*configPath); err != nil {
		log.Fatalf("[FATAL] Ошибка загрузки конфига: %v", err)
	}

	cfg := core.GlobalConfig

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Mode == "server" {
		log.Printf("[SERVER] Запуск узла на %s (Маскировка: %s)\n", cfg.ListenAddr, cfg.DecoyURL)
		go runServer(cfg.ListenAddr)
	} else {
		log.Println("[CLIENT] Запуск клиентского модуля...")
		go runClientLoop(ctx, cfg)
	}

	<-ctx.Done()
	fmt.Println("\n[GR3M] Получен сигнал завершения. Закрытие всех соединений...")

	time.Sleep(1 * time.Second)
	log.Println("[GR3M] Работа завершена.")
}

func runServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[SERVER] Не удалось занять порт %s: %v", addr, err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}

		go func(c net.Conn) {

			session, err := core.PerformHandshake(c, true)
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
			log.Println("[CLIENT] Поиск самого быстрого сервера из списка пиров...")
			fastest := core.GetFastestPeer()

			if fastest == "" {
				log.Println("[!] Все сервера недоступны. Повторная попытка через 5 секунд...")
				time.Sleep(5 * time.Second)
				continue
			}

			log.Printf("[CLIENT] Выбран сервер: %s. Установка туннеля...\n", fastest)

			err := startTunnel(fastest, cfg.SocksAddr)
			if err != nil {
				log.Printf("[!] Ошибка туннеля: %v. Ищем новый сервер...\n", err)
				time.Sleep(2 * time.Second)
			}
		}
	}
}

func startTunnel(remote, socks string) error {
	conn, err := net.DialTimeout("tcp", remote, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	session, err := core.PerformHandshake(conn, false)
	if err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}

	log.Printf("[SUCCESS] Туннель поднят. SOCKS5 прокси активен на %s\n", socks)

	errChan := make(chan error, 1)

	go client.StartSocks5(socks, conn, session.EncryptionKey, errChan)

	return <-errChan
}
