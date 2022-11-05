package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/kinyoubenkyokai/yuberify/lib"
	"io"
	"os"
	"path/filepath"
)

type Subject struct {
	PublicKey *ecdsa.PublicKey
	Yubico    lib.SignPin
}

func CreateSubject() (Subject, error) {
	p, err := filepath.Abs("./tmp/public-key.pem")
	if err != nil {
		return Subject{}, err
	}
	f, err := os.Open(p)
	if err != nil {
		return Subject{}, err
	}
	pubkeyBytes, err := io.ReadAll(f)
	if err != nil {
		return Subject{}, err
	}
	block, _ := pem.Decode(pubkeyBytes)
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	subject := Subject{
		PublicKey: publicKey,
		Yubico:    lib.NewSignPin(),
	}

	return subject, err
}

func (s Subject) GetID() ([]byte, error) {
	return EncodePublic(s.PublicKey)
}

// EncodePublic public key
func EncodePublic(pubKey *ecdsa.PublicKey) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return []byte{}, err
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})

	return pemEncodedPub, nil
}

func (s Subject) SignPresentation(credentials Credential, nonce []byte) (Presentation, error) {
	presentation := Presentation{
		PresentationToSign: PresentationToSign{
			Context:            vcContext,
			TypeOfPresentation: []string{presType},
			Credential:         credentials,
			Nonce:              nonce,
		}}

	docToSign, err := presentation.Export()
	if err != nil {
		return presentation, err
	}
	sig, err := SignProofHolder(s, docToSign)
	if err != nil {
		return presentation, err
	}
	presentation.Proof = sig
	return presentation, err
}
