package key

import (
	ecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"time"
)

func GenerateECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func GetPublicKeyFromECDSAPrivateKey(in *ecdsa.PrivateKey) *ecdsa.PublicKey {
	return &in.PublicKey
}

func CreateX509FromECDSAPrivateKey(key *ecdsa.PrivateKey, filename string) (*pem.Block, error) {
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ECDSA key: %w", err)
	}
	keyBlock := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}
	keyFile, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open ec_key.pem for writing: %w", err)
	}
	defer func() {
		keyFile.Close()
	}()

	if err := pem.Encode(keyFile, &keyBlock); err != nil {
		return nil, fmt.Errorf("failed to write data to ec_key.pem: %w", err)
	}

	return &keyBlock, nil
}

func GenerateCert(pub, priv any, filename string) (*pem.Block, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Docker, Inc."},
		},
		NotBefore: time.Now().Add(-time.Hour * 24 * 365),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
	}
	certDer, err := x509.CreateCertificate(
		rand.Reader, &template, &template, pub, priv,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	certFile, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open '%s' for writing: %w", filename, err)
	}
	defer func() {
		certFile.Close()
	}()

	pem.Encode(certFile, &certBlock)

	return &certBlock, nil
}

func GeneratePKCS12(cert *pem.Block, prv *ecdsa.PrivateKey, filename string, password string) ([]byte, error) {
	cert2, err := x509.ParseCertificate(cert.Bytes)
	if err != nil {
		return nil, err
	}
	pfx, err := pkcs12.Encode(rand.Reader, prv, cert2, []*x509.Certificate{}, password)
	if err != nil {
		return nil, err
	}

	// check if pfxBytes valid
	_, _, _, err = pkcs12.DecodeChain(pfx, password)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(
		filename,
		pfx,
		os.ModePerm,
	); err != nil {
		panic(err)
	}
	return pfx, nil
}
