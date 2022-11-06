package yubico

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"os/exec"
	"strings"
)

type Yubikey struct {
	yk *piv.YubiKey
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

func (s *Yubikey) ImportKey() (crypto.PublicKey, error) {
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyNever,
	}
	return s.yk.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
}

func (s *Yubikey) VerifyByYubikey(pub crypto.PublicKey, text []byte, pin int32) ([]byte, error) {
	auth := piv.KeyAuth{PIN: fmt.Sprintf("%d", pin)}
	priv, err := s.yk.PrivateKey(piv.SlotSignature, pub, auth)
	if err != nil {
		return nil, err
	}
	signed, err := priv.(*piv.ECDSAPrivateKey).Sign(rand.Reader, text, crypto.SHA256)
	return signed, err
}

func ImportKeyToYubikeySlot(pkcsByte []byte, password string) ([]byte, error) {
	cmd := exec.Command("yubico-piv-tool",
		"-s", "9c",
		"-K", "PKCS12",
		"-a", "set-chuid",
		"-a", "import-key",
		"-a", "import-cert",
		"-p", password,
		"-i", "./tmp/pkcs12.p12",
	)
	return RunCmd(*cmd, pkcsByte)
}
