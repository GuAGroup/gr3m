// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"gr3m/key"
)

func main() {
	fmt.Println("--- GR3M Key Generator ---")

	priv, err, pub := key.GenPrvKeyAndPublic()
	if err != nil {
		log.Fatalf("Ошибка генерации: %v", err)
	}

	hash := sha256.Sum256(pub[:])
	pubHash := hex.EncodeToString(hash[:])

	fmt.Println("\n[!] СОХРАНИ ЭТИ ДАННЫЕ В ТАЙНЕ:")
	fmt.Printf("Private Key (hex): %x\n", priv)
	fmt.Printf("Public Key (hex):  %x\n", pub)

	fmt.Println("\n[+] ДАННЫЕ ДЛЯ config.json (КЛИЕНТ):")
	fmt.Printf("\"pub_key\": \"%s\"\n", pubHash)

	fmt.Println("\n[+] ДАННЫЕ ДЛЯ СЕРВЕРА (ENV или CONFIG):")
	fmt.Printf("SERVER_PRIV_KEY=%x\n", priv)
	fmt.Println("--------------------------")
}
