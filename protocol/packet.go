package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"hub.mos.ru/gua/crypto-lib/src/crypto"
)

const (
	MinPadding = 64
	MaxPadding = 512
)

func Pack(streamID uint32, data []byte, encKey []byte) ([]byte, error) {
	compressed, err := crypto.Compress(data)
	if err != nil {
		return nil, err
	}

	padSize := MinPadding + (int(getRandomByte()) % (MaxPadding - MinPadding))

	// [StreamID(4) | DataLen(4) | Data | Padding]
	raw := make([]byte, 8+len(compressed)+padSize)
	binary.BigEndian.PutUint32(raw[0:4], streamID)
	binary.BigEndian.PutUint32(raw[4:8], uint32(len(compressed)))
	copy(raw[8:8+len(compressed)], compressed)

	_, _ = io.ReadFull(rand.Reader, raw[8+len(compressed):])

	return crypto.EncryptChaCha(encKey, raw)
}

func Unpack(cipherFrame []byte, encKey []byte) (uint32, []byte, error) {
	decrypted, err := crypto.DecryptChaCha(encKey, cipherFrame)
	if err != nil {
		return 0, nil, fmt.Errorf("HYSTERIA_TRIGGER")
	}

	if len(decrypted) < 8 {
		return 0, nil, fmt.Errorf("too short")
	}

	id := binary.BigEndian.Uint32(decrypted[0:4])
	l := binary.BigEndian.Uint32(decrypted[4:8])

	if int(l) > len(decrypted)-8 {
		return 0, nil, fmt.Errorf("length mismatch")
	}

	data, err := crypto.Decompress(decrypted[8 : 8+l])
	return id, data, err
}

func getRandomByte() byte {
	b := make([]byte, 1)
	rand.Read(b)
	return b[0]
}
