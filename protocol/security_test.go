// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"testing"
)

func TestFullSecurityCycle(t *testing.T) {
	key := []byte("32-byte-long-secret-key-for-test")
	state := &SessionState{Key: key}

	data := []byte("Hello, Secure World!")

	packet, err := state.Pack(1, data)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	id, decrypted, err := state.Unpack(packet)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	if !bytes.Equal(decrypted, data) || id != 1 {
		t.Errorf("Decrypted data mismatch")
	}

	_, _, err = state.Unpack(packet)
	if err == nil {
		t.Error("Security Breach: Replay attack successful, but should have failed")
	}
}
