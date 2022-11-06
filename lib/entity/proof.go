package entity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"time"
)

const ecdsaType = "ecdsasecp256k1signature2019"

type Proof struct {
	TypeOfProof string           `json:"type"`
	Created     time.Time        `json:"created"`
	Creator     crypto.PublicKey `json:"creator"`
	Signature   []byte           `json:"signature"`
}

func SignProofIssuer(keys KeyPair, docToSign []byte) (Proof, error) {
	proof := Proof{
		TypeOfProof: ecdsaType,
		Created:     time.Now(),
		Creator:     keys.PublicKey,
	}

	hash := sha256.Sum256(docToSign)
	sig, err := keys.PrivateKey.(*ecdsa.PrivateKey).Sign(rand.Reader, hash[:], nil)
	if err != nil {
		return Proof{}, err
	}
	proof.Signature = sig

	return proof, nil
}

type RawSignature struct {
	R, S *big.Int
}
