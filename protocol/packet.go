// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"hub.mos.ru/gua/crypto-lib/src/crypto"
)

type SessionState struct {
	Key      []byte
	InNonce  uint64
	OutNonce uint64
}

func (s *SessionState) Pack(streamID uint32, data []byte) ([]byte, error) {
	s.OutNonce++
	compressed, err := crypto.Compress(data)
	if err != nil {
		return nil, err
	}

	padLen := 64 + (int(getRandomByte()) % 192)
	raw := make([]byte, 16+len(compressed)+padLen)

	binary.BigEndian.PutUint64(raw[0:8], s.OutNonce)
	binary.BigEndian.PutUint32(raw[8:12], streamID)
	binary.BigEndian.PutUint32(raw[12:16], uint32(len(compressed)))
	copy(raw[16:16+len(compressed)], compressed)

	_, _ = io.ReadFull(rand.Reader, raw[16+len(compressed):])
	return crypto.EncryptChaCha(s.Key, raw)
}

func (s *SessionState) Unpack(cipherFrame []byte) (uint32, []byte, error) {
	decrypted, err := crypto.DecryptChaCha(s.Key, cipherFrame)
	if err != nil {
		return 0, nil, fmt.Errorf("SECURITY_ERR: Integrity check failed")
	}

	if len(decrypted) < 16 {
		return 0, nil, fmt.Errorf("packet too short")
	}

	nonce := binary.BigEndian.Uint64(decrypted[0:8])
	if nonce <= s.InNonce {
		return 0, nil, fmt.Errorf("REPLAY_ATTACK_DETECTED")
	}
	s.InNonce = nonce

	id := binary.BigEndian.Uint32(decrypted[8:12])
	l := binary.BigEndian.Uint32(decrypted[12:16])

	if int(l) > len(decrypted)-16 {
		return 0, nil, fmt.Errorf("invalid length")
	}

	data, err := crypto.Decompress(decrypted[16 : 16+l])
	return id, data, err
}

func getRandomByte() byte {
	b := make([]byte, 1)
	rand.Read(b)
	return b[0]
}
