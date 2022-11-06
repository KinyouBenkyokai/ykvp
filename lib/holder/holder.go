package holder

import (
	"crypto"
	"crypto/ecdsa"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/kinyoubenkyokai/yuberify/lib"
	"github.com/kinyoubenkyokai/yuberify/lib/entity"
	"github.com/kinyoubenkyokai/yuberify/lib/yubico"
	"time"
)

const (
	presType = "VerifiablePresentation"
	vcSpec   = "https://www.w3.org/2018/credentials/v1"
)

const ecdsaType = "ecdsasecp256k1signature2019"

var vcContext = []string{vcSpec}

type Holder struct {
	PublicKey crypto.PublicKey
	Yubico    *yubico.Yubikey
}

func CreateHolder(pub *ecdsa.PublicKey) (Holder, error) {
	yk, err := yubico.NewYubikey()
	if err != nil {
		return Holder{}, err
	}
	holder := Holder{
		PublicKey: pub,
		Yubico:    yk,
	}
	return holder, nil
}

func (s Holder) GetSubject() (verifiable.Subject, error) {
	id, err := lib.EncodePublic(s.PublicKey)
	if err != nil {
		return verifiable.Subject{}, err
	}
	return verifiable.Subject{
		ID:           string(id),
		CustomFields: nil,
	}, nil
}

func (s Holder) SignPresentation(credentials entity.Credential, nonce []byte, yubikeyPIN int32) (entity.Presentation, error) {
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

func SignProofHolderWithYubikey(s Holder, docToSign []byte, yubikeyPIN int32) (entity.Proof, error) {
	sig, err := s.Yubico.SignByYubikey(s.PublicKey, docToSign, yubikeyPIN)
	if err != nil {
		return entity.Proof{}, err
	}
	proof := entity.Proof{
		TypeOfProof: ecdsaType,
		Created:     time.Now(),
		Creator:     s.PublicKey,
		Signature:   sig,
	}
	return proof, nil
}
