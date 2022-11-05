package entity

import (
	"crypto/ecdsa"
)

type KeyPair struct {
	PublicKey  *ecdsa.PublicKey
	PrivateKey *ecdsa.PrivateKey
}
