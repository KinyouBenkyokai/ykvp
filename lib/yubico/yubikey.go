package yubico

import (
	crypto "crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"strings"
)

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=yubico

type pivYubikey interface {
	PrivateKey(slot piv.Slot, pub crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error)
	GenerateKey(key [24]byte, slot piv.Slot, keyTemplate piv.Key) (crypto.PublicKey, error)
	Close() error
}

type Yubikey struct {
	yk pivYubikey
}

func NewYubikey() (*Yubikey, error) {
	yk, err := getYubikey()
	if err != nil {
		return nil, err
	}
	return &Yubikey{yk: yk}, nil
}

func (s *Yubikey) Close() error {
	return s.yk.Close()
}

func getYubikey() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				return nil, err
			}
			break
		}
	}
	if yk == nil {
		return nil, fmt.Errorf("no YubiKey found")
	}
	return yk, nil
}

func (s *Yubikey) GenerateKey() (crypto.PublicKey, error) {
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	return s.yk.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
}

func (s *Yubikey) SignByYubikey(pub crypto.PublicKey, text []byte, pin int32) ([]byte, error) {
	auth := piv.KeyAuth{
		PIN:       fmt.Sprintf("%d", pin),
		PINPolicy: piv.PINPolicyAlways,
	}
	priv, err := s.yk.PrivateKey(piv.SlotSignature, pub, auth)
	if err != nil {
		return nil, err
	}
	data := sha256.Sum256(text)
	cs, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("expected private key to implement crypto.Signer")
	}
	fmt.Println("please touch yubikey...")
	signed, err := cs.Sign(rand.Reader, data[:], crypto.SHA256)
	return signed, err
}
