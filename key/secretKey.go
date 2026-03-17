// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package key

import (
	"fmt"
	"log"

	"hub.mos.ru/gua/crypto-lib/src/crypto"
)

// Gen secret key
func GenSecretKey(pubkey [32]byte, privkey [32]byte) ([32]byte, error) {
	secretSlice, err := crypto.DeriveSharedSecret(privkey, pubkey)
	if err != nil {
		log.Printf("Error secret key: %v", err)
		return [32]byte{}, err
	}

	if len(secretSlice) != 32 {
		return [32]byte{}, fmt.Errorf("unexpected secret length: %d", len(secretSlice))
	}

	var secretArray [32]byte
	copy(secretArray[:], secretSlice)

	return secretArray, nil
}

// kdf
func SetupSessionKeys(sharedSecret []byte) (encKey, macKey []byte, err error) {
	salt := []byte("gr3m-salt")
	encKey, err = crypto.DeriveKeyHKDF(sharedSecret, salt, "encryption-key")
	if err != nil {
		return
	}
	macKey, err = crypto.DeriveKeyHKDF(sharedSecret, salt, "integrity-check")
	if err != nil {
		return
	}
	return
}
