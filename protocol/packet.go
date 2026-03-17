// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package protocol

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"

	"golang.org/x/crypto/chacha20poly1305"
)

type SessionState struct {
	Key      []byte
	OutNonce uint64
	InNonce  uint64
}

func (s *SessionState) Pack(id uint32, payload []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(s.Key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], s.OutNonce)
	s.OutNonce++

	header := make([]byte, 16)
	binary.BigEndian.PutUint64(header[0:8], s.OutNonce)
	binary.BigEndian.PutUint32(header[8:12], id)
	binary.BigEndian.PutUint32(header[12:16], uint32(len(payload)))

	rawPacket := append(header, payload...)

	currentLen := len(rawPacket)
	targetLen := ((currentLen + 63) / 64) * 64
	paddingLen := targetLen - currentLen

	extraJitter := rand.IntN(64)
	totalPadding := paddingLen + extraJitter

	padding := make([]byte, totalPadding)
	if _, err := crand.Read(padding); err != nil {
		return nil, err
	}

	finalRaw := append(rawPacket, padding...)
	encrypted := aead.Seal(nil, nonce, finalRaw, nil)

	return encrypted, nil
}

func (s *SessionState) Unpack(encrypted []byte) (uint32, []byte, error) {
	if len(encrypted) < chacha20poly1305.NonceSize {
		return 0, nil, errors.New("packet too short")
	}

	aead, err := chacha20poly1305.New(s.Key)
	if err != nil {
		return 0, nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], s.InNonce)

	decrypted, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("decryption failed: %v", err)
	}

	seqNum := binary.BigEndian.Uint64(decrypted[0:8])
	if seqNum <= s.InNonce {
		return 0, nil, errors.New("replay attack detected")
	}
	s.InNonce = seqNum

	streamID := binary.BigEndian.Uint32(decrypted[8:12])
	payloadLen := binary.BigEndian.Uint32(decrypted[12:16])

	if int(16+payloadLen) > len(decrypted) {
		return 0, nil, errors.New("invalid payload length")
	}

	payload := decrypted[16 : 16+payloadLen]

	return streamID, payload, nil
}
