// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package protocol

import (
	"testing"
)

func TestSecurityIntegrity(t *testing.T) {
	key := []byte("very-secret-key-32-bytes-long-!!")
	state := &SessionState{Key: key}

	originalData := []byte("Sensitive Information")
	packet, err := state.Pack(100, originalData)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	id, decrypted, err := state.Unpack(packet)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	if id != 100 || string(decrypted) != string(originalData) {
		t.Error("Data corruption during transit")
	}

	_, _, err = state.Unpack(packet)
	if err == nil {
		t.Error("Security Fail: Replay attack possible! System accepted duplicate nonce.")
	}

	state2 := &SessionState{Key: key, InNonce: 10}
	packet2, _ := state2.Pack(1, []byte("valid"))
	packet2[len(packet2)-1] ^= 0xFF

	_, _, err = state2.Unpack(packet2)
	if err == nil {
		t.Error("Security Fail: Modified packet was accepted (Integrity breach)")
	}
}
