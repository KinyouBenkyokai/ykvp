package issuer

import (
	"fmt"
	"github.com/kinyoubenkyokai/yuberify/lib/entity"
	"github.com/kinyoubenkyokai/yuberify/lib/key"
	"time"
)

const (
	vcType = "VerifiableCredential"
	vcSpec = "https://www.w3.org/2018/credentials/v1"
)

var vcContext = []string{vcSpec}

type Issuer struct {
	keys entity.KeyPair

	ID   string
	Name string
}

func CreateIssuer(id, name string) (Issuer, error) {
	privateKey, err := key.NewGenerateKey().GenerateECDSAPrivateKey()
	if err != nil {
		return Issuer{}, fmt.Errorf("couldn't create issuer keys: %w", err)
	}
	pub := key.NewGenerateKey().GetPublicKeyFromECDSAPrivateKey(privateKey)
	issuer := Issuer{
		keys: entity.KeyPair{PublicKey: pub, PrivateKey: privateKey},
		ID:   id,
		Name: name,
	}
	return issuer, err
}

func (i Issuer) SignCredential(claim entity.Claim, subjectID []byte) (entity.Credential, error) {
	creds := entity.Credential{CredentialToSign: entity.CredentialToSign{
		Context:          vcContext,
		TypeOfCredential: append(claim.GetType(), vcType),
		IssuanceDate:     time.Now(),
		CredentialSubject: entity.CredentialSubject{
			ID:    subjectID,
			Claim: claim,
		},
	}}

	docToSign, err := creds.Export()
	if err != nil {
		return creds, err
	}

	creds.Proof = entity.SignProofIssuer(i.keys, docToSign)
	return creds, err
}
