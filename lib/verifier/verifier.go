package verifier

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"github.com/kinyoubenkyokai/yuberify/lib"
	"github.com/kinyoubenkyokai/yuberify/lib/entity"
	"math/big"
	"math/rand"
)

const (
	nonceSize = 12
)

type Verifier struct{}

func CreateVerifier() Verifier {
	return Verifier{}
}

func (v Verifier) MakeNonce() (nonce []byte, err error) {
	nonce = make([]byte, nonceSize)
	_, err = rand.Read(nonce)
	return nonce, err
}

func (v Verifier) VerifiesPresentation(presentation entity.Presentation, holderPubkey crypto.PublicKey) (err error) {
	credential := presentation.Credential

	// A - Checks the Presentation is signed by the Subject of the credential
	credentialSubjectID := credential.CredentialSubject.ID
	presentationProver := presentation.Proof.Creator
	b, err := lib.EncodePublic(presentationProver)
	if err != nil {
		return err
	}
	if bytes.Compare(credentialSubjectID, b) != 0 {
		return fmt.Errorf("Presentation prover is not the credential subject.")
	}

	// B - Checks the credential
	signedCred, err := credential.Export()
	if err != nil {
		return fmt.Errorf(
			"Couldn't export credential to verify signature: %w", err,
		)
	}

	okCred := verifiesSignature(credential.Proof.Creator, credential.Proof.Signature, signedCred)
	if !okCred {
		return fmt.Errorf("Invalid credential signature.")
	}

	// C - Checks the presentation
	signedPres, err := presentation.Export()
	if err != nil {
		return fmt.Errorf(
			"Couldn't export presentation to verify signature: %w", err,
		)
	}

	okPres := verifiesSignature(holderPubkey, presentation.Proof.Signature, signedPres)
	if !okPres {
		return fmt.Errorf("Invalid presentation signature.")
	}

	return err
}

func verifiesSignature(pubKey crypto.PublicKey, signature, signedDoc []byte) bool {
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		return false
	}

	hasher := crypto.Hash.New(crypto.SHA256)
	hasher.Write(signedDoc)
	if !ecdsa.Verify(pub, hasher.Sum(nil), sig.R, sig.S) {
		return false
	}
	return true
}
