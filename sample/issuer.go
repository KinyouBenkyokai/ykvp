package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"
)

type Issuer struct {
	keys KeyPair

	ID   string
	Name string
}

const vcSpec = "https://www.w3.org/2018/credentials/v1"

var vcContext = []string{vcSpec}

func CreateIssuer(id, name string) (Issuer, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		err = fmt.Errorf("Couldn't create issuer keys: %w", err)
		return Issuer{}, err
	}
	pub := privateKey.PublicKey
	issuer := Issuer{
		keys: KeyPair{PublicKey: &pub, PrivateKey: privateKey},
		ID:   id,
		Name: name,
	}

	return issuer, err
}

func (i Issuer) SignCredential(claim Claim, subjectID []byte) (Credential, error) {
	creds := Credential{CredentialToSign: CredentialToSign{
		Context:          vcContext,
		TypeOfCredential: append(claim.GetType(), vcType),
		Issuer:           i,
		IssuanceDate:     time.Now(),
		CredentialSubject: CredentialSubject{
			ID:    subjectID,
			Claim: claim,
		},
	}}

	docToSign, err := creds.Export()
	if err != nil {
		return creds, err
	}

	creds.Proof = SignProofIssuer(i.keys, docToSign)
	return creds, err
}
