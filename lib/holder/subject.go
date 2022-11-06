package holder

import (
	"crypto"
	"crypto/ecdsa"
	"github.com/kinyoubenkyokai/yuberify/lib"
	"github.com/kinyoubenkyokai/yuberify/lib/entity"
	"github.com/kinyoubenkyokai/yuberify/lib/yubico"
	"time"
)

const (
	presType = "VerifiablePresentation"
	vcSpec   = "https://www.w3.org/2018/credentials/v1"
)

const ed25519Type = "Ed25519Signature2018"

var vcContext = []string{vcSpec}

type Subject struct {
	PublicKey crypto.PublicKey
	Yubico    *yubico.Yubikey
}

func CreateSubject(pub *ecdsa.PublicKey) (Subject, error) {
	yk, err := yubico.NewYubikey()
	if err != nil {
		return Subject{}, err
	}
	subject := Subject{
		PublicKey: pub,
		Yubico:    yk,
	}
	return subject, nil
}

func (s Subject) GetID() ([]byte, error) {
	return lib.EncodePublic(s.PublicKey)
}

func (s Subject) SignPresentation(credentials entity.Credential, nonce []byte, yubikeyPIN int32) (entity.Presentation, error) {
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
	sig, err := SignProofHolderWithYubikey(s, docToSign, yubikeyPIN)
	if err != nil {
		return presentation, err
	}
	presentation.Proof = sig
	return presentation, err
}

func SignProofHolderWithYubikey(s Subject, docToSign []byte, yubikeyPIN int32) (entity.Proof, error) {
	sig, err := s.Yubico.SignByYubikey(s.PublicKey, docToSign, yubikeyPIN)
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
