package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"time"
)

const ed25519Type = "Ed25519Signature2018"

type Proof struct {
	TypeOfProof string           `json:"type"`
	Created     time.Time        `json:"created"`
	Creator     *ecdsa.PublicKey `json:"creator"`
	Signature   []byte           `json:"signature"`
}

func SignProofHolder(s Subject, docToSign []byte) (Proof, error) {
	sig, err := s.Yubico.VerifyByYubikey(docToSign, 123456)
	if err != nil {
		return Proof{}, err
	}
	proof := Proof{
		TypeOfProof: ed25519Type,
		Created:     time.Now(),
		Creator:     s.PublicKey,
		Signature:   sig,
	}
	return proof, nil
}

func SignProofIssuer(keys KeyPair, docToSign []byte) Proof {
	proof := Proof{
		TypeOfProof: ed25519Type,
		Created:     time.Now(),
		Creator:     keys.PublicKey,
	}

	hash := sha256.Sum256(docToSign)
	r, s, _ := ecdsa.Sign(rand.Reader, keys.PrivateKey, hash[:])
	asn1Signature, _ := asn1.Marshal(rawSignature{r, s})
	proof.Signature = asn1Signature

	return proof
}

type rawSignature struct {
	R, S *big.Int
}

func export(i interface{}) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	err := e.Encode(i)
	return buf.Bytes(), err
}
