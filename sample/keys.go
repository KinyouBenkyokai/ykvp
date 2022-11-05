package main

import (
	"crypto/ecdsa"
)

type KeyPair struct {
	PublicKey  *ecdsa.PublicKey
	PrivateKey *ecdsa.PrivateKey
}
