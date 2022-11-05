package entity

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
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

func SignProofIssuer(keys KeyPair, docToSign []byte) Proof {
	proof := Proof{
		TypeOfProof: ed25519Type,
		Created:     time.Now(),
		Creator:     keys.PublicKey,
	}

	hash := sha256.Sum256(docToSign)
	r, s, _ := ecdsa.Sign(rand.Reader, keys.PrivateKey, hash[:])
	asn1Signature, _ := asn1.Marshal(RawSignature{r, s})
	proof.Signature = asn1Signature

	return proof
}

type RawSignature struct {
	R, S *big.Int
}
