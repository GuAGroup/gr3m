// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"gr3m/config"
	"log"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Ошибка загрузки: %v", err)
	}

	fmt.Printf("Конфиг: %s\n", cfg.GetConfigName())
	fmt.Printf("Истерия активна: %v\n", cfg.GetHysteria())
	fmt.Printf("Публичный ключ: %v\n", cfg.GetPublicKey())

	if len(cfg.GetServerIps()) > 0 {
		fmt.Printf("Первый IP: %s\n", cfg.GetServerIps()[0])
	}
}
