package holder

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/kinyoubenkyokai/yuberify/lib"
	"github.com/kinyoubenkyokai/yuberify/lib/entity"
	"github.com/kinyoubenkyokai/yuberify/lib/yubico"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	presType = "VerifiablePresentation"
	vcSpec   = "https://www.w3.org/2018/credentials/v1"
)

const ed25519Type = "Ed25519Signature2018"

var vcContext = []string{vcSpec}

type Subject struct {
	PublicKey *ecdsa.PublicKey
	Yubico    yubico.SignPin
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
		Yubico:    yubico.NewSignPin(),
	}

	return subject, err
}

func (s Subject) GetID() ([]byte, error) {
	return lib.EncodePublic(s.PublicKey)
}

func (s Subject) SignPresentation(credentials entity.Credential, nonce []byte) (entity.Presentation, error) {
	presentation := entity.Presentation{
		PresentationToSign: entity.PresentationToSign{
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

func SignProofHolder(s Subject, docToSign []byte) (entity.Proof, error) {
	sig, err := s.Yubico.VerifyByYubikey(docToSign, 123456)
	if err != nil {
		return entity.Proof{}, err
	}
	proof := entity.Proof{
		TypeOfProof: ed25519Type,
		Created:     time.Now(),
		Creator:     s.PublicKey,
		Signature:   sig,
	}
	return proof, nil
}
