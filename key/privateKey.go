// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package key

import (
	"log"

	"hub.mos.ru/gua/crypto-lib/src/crypto"
)

// Gen Private Key & Public
func GenPrvKeyAndPublic() ([32]byte, error, [32]byte) {
	prvKey, pubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
		return [32]byte{}, err, [32]byte{}
	}
	return prvKey, err, pubKey
}
