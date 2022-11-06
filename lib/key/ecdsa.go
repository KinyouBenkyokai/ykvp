package key

import (
	ecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"time"
)

type GenerateKey struct {
	createFile bool
	fileName   string
}

func NewGenerateKey() *GenerateKey {
	return &GenerateKey{createFile: false, fileName: ""}
}

type option func(*GenerateKey)

func SetCreateFiles(filename string) option {
	return func(g *GenerateKey) {
		g.createFile = true
		g.fileName = filename
	}
}

func (g *GenerateKey) GenerateECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (g *GenerateKey) GetPublicKeyFromECDSAPrivateKey(in *ecdsa.PrivateKey) *ecdsa.PublicKey {
	return &in.PublicKey
}

func (g *GenerateKey) CreateX509FromECDSAPrivateKey(key *ecdsa.PrivateKey, opts ...option) (*pem.Block, error) {
	for _, opt := range opts {
		opt(g)
	}

	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ECDSA key: %w", err)
	}
	keyBlock := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	var out io.WriteCloser
	if g.createFile {
		out, err = os.Create(g.fileName)
		if err != nil {
			return nil, fmt.Errorf("failed to open ec_key.pem for writing: %w", err)
		}
		defer out.Close()
	} else {
		out = os.Stdout
	}

	if err := pem.Encode(out, &keyBlock); err != nil {
		return nil, fmt.Errorf("failed to write data to ec_key.pem: %w", err)
	}

	return &keyBlock, nil
}

func (g *GenerateKey) GenerateCert(pub, priv any, opts ...option) (*pem.Block, error) {
	for _, opt := range opts {
		opt(g)
	}
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

	if g.createFile {
		certFile, err := os.Create(g.fileName)
		if err != nil {
			return nil, fmt.Errorf("failed to open '%s' for writing: %w", g.fileName, err)
		}
		defer certFile.Close()
		pem.Encode(certFile, &certBlock)
	}

	return &certBlock, nil
}

func (g *GenerateKey) GeneratePKCS12(cert *pem.Block, prv *ecdsa.PrivateKey, password string, opts ...option) ([]byte, error) {
	for _, opt := range opts {
		opt(g)
	}

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

	if g.createFile {
		if err := createFile(g.fileName, pfx); err != nil {
			return nil, err
		}
	}
	return pfx, nil
}

func createFile(filename string, b []byte) error {
	if err := os.WriteFile(
		filename, b, os.ModePerm,
	); err != nil {
		return err
	}
	return nil
}
