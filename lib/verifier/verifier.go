package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"github.com/kinyoubenkyokai/yuberify/lib"
	"github.com/kinyoubenkyokai/yuberify/lib/entity"
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

func (v Verifier) VerifiesPresentation(presentation entity.Presentation) (err error) {
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

	okCred := verifiesSignature(credential.Proof, signedCred)
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

	okPres := verifiesSignature(presentation.Proof, signedPres)
	if !okPres {
		return fmt.Errorf("Invalid presentation signature.")
	}

	return err
}

func verifiesSignature(proof entity.Proof, signedDoc []byte) bool {
	pubKey := proof.Creator
	signature := proof.Signature
	var sig entity.RawSignature
	asn1.Unmarshal(signature, &sig)
	hash := sha256.Sum256([]byte(signedDoc))
	return ecdsa.Verify(pubKey, hash[:], sig.R, sig.S)
}
