package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"gr3m/client"
	"gr3m/core"
	"gr3m/server"
)

func main() {
	cfgPath := flag.String("c", "config.json", "path to config")
	flag.Parse()

	if err := core.LoadConfig(*cfgPath); err != nil {
		log.Fatal("Ошибка конфигурации:", err)
	}

	cfg := core.GlobalConfig

	if cfg.Mode == "server" {
		runServer(cfg.ListenAddr)
	} else {
		for {
			fmt.Println("[GR3M] Поиск лучшего пира...")
			fastest := core.GetFastestPeer()

			if fastest == "" {
				fmt.Println("[!] Все пиры недоступны. Повтор через 5 секунд...")
				time.Sleep(5 * time.Second)
				continue
			}

			fmt.Printf("[GR3M] Подключение к %s\n", fastest)
			err := runClient(fastest, cfg.SocksAddr)

			if err != nil {
				fmt.Printf("[!] Соединение разорвано: %v. Реконнект...\n", err)
				time.Sleep(3 * time.Second)
			}
		}
	}
}

func runServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[SERVER] Боевой режим активен на %s\n", addr)
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

func runClient(remote, socks string) error {
	conn, err := net.DialTimeout("tcp", remote, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	session, err := core.PerformHandshake(conn, false)
	if err != nil {
		return err
	}

	fmt.Printf("[GR3M] Туннель готов. SOCKS5: %s\n", socks)

	errChan := make(chan error)
	go client.StartSocks5(socks, conn, session.EncryptionKey, errChan)

	return <-errChan
}
