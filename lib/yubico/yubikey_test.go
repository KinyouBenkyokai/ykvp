package yubico

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestYubiKeySignECDSA(t *testing.T) {
	yk, err := NewYubikey()
	defer yk.Close()
	if err := yk.yk.Reset(); err != nil {
		t.Fatalf("reset yubikey: %v", err)
	}

	pubKey, err := yk.GenerateKey()
	out, err := yk.SignByYubikey(pubKey, []byte("hello"), 123456)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(out, &sig); err != nil {
		t.Fatalf("unmarshaling signature: %v", err)
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not an ecdsa key")
	}
	data := sha256.Sum256([]byte("hello"))
	if !ecdsa.Verify(pub, data[:], sig.R, sig.S) {
		t.Errorf("signature didn't match")
	}
}
