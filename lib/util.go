package lib

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
)

// EncodePublic public key
func EncodePublic(pubKey crypto.PublicKey) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return []byte{}, err
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})

	return pemEncodedPub, nil
}

func Export(i interface{}) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	err := e.Encode(i)
	return buf.Bytes(), err
}
