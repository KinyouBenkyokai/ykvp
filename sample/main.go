package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/kinyoubenkyokai/yuberify/lib/entity"
	"github.com/kinyoubenkyokai/yuberify/lib/holder"
	"github.com/kinyoubenkyokai/yuberify/lib/issuer"
	"github.com/kinyoubenkyokai/yuberify/lib/verifier"
	"github.com/kinyoubenkyokai/yuberify/lib/yubico"
	"os"
)

const (
	issuerID   = "https://oxford.com/issuers/1" // This is a fake URL.
	issuerName = "The Marvelous University of Oxford"
)

func main() {
	holderPubkey, err := yubico.GenerateAndImportKeyToYubikey()
	if err != nil {
		panic(err)
	}

	// Part I: Create the issuer, the subject, and the verifier.
	issuer, holder, err := part1(holderPubkey)
	if err != nil {
		panic(err)
	}

	// Part II: Create credentials for the subject.
	subject, err := holder.GetSubject()
	if err != nil {
		panic(err)
	}
	credentials, err := part2(issuer, subject)
	if err != nil {
		panic(err)
	}
	verifier := verifier.CreateVerifier()

	// Part III: Verify the credentials.
	if err := part3(holder, verifier, credentials, holderPubkey); err != nil {
		panic(err)
	}
}

// part1 creates an issuer and a subject.
func part1(pub *ecdsa.PublicKey) (issuer.Issuer, holder.Holder, error) {
	// Part I: Create the issuer, the subject, and the verifier.
	issuer, err := issuer.CreateIssuer(issuerID, issuerName)
	if err != nil {
		panic(err)
	}

	holder, err := holder.CreateHolder(pub)
	return issuer, holder, err
}

// part2 creates credentials for the subject.
func part2(issuer issuer.Issuer, subject verifiable.Subject) (entity.Credential, error) {
	// Step 1: Create a Holder and a claim to sign about this subject.
	// The claim is created jointly by the Holder and the Issuer. How they come
	// to agree on the claim to sign is out of scope here.
	claim := entity.Claim{
		Age:            24,
		UniversityName: "Oxford",
		Degree:         "Bachelor of Science",
	}
	nicePrint(claim, "Claim")

	// Step 2: The Issuer signs the claim about this subject.
	credentials, err := issuer.SignCredential(claim, []byte(subject.ID))
	if err != nil {
		err = fmt.Errorf("issuer couldn't sign credentials: %w", err)
		return credentials, err
	}

	nicePrint(credentials, "Credential")
	return credentials, err
}

// part3 verifies the credentials.
func part3(holder holder.Holder, verifier verifier.Verifier, credentials entity.Credential, holderPubkey *ecdsa.PublicKey) error {
	nonce, err := verifier.MakeNonce()
	if err != nil {
		return err
	}

	presentation, err := holder.SignPresentation(
		credentials,
		nonce,
		123456,
	)
	if err != nil {
		return err
	}

	nicePrint(presentation, "Presentation")

	err = verifier.VerifiesPresentation(presentation, holderPubkey)
	if err != nil {
		return fmt.Errorf("Verificiation failed: %w", err)
	}
	fmt.Println("\n!!! Verification succeeded !!!")
	return nil
}

func nicePrint(i interface{}, name string) {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")

	fmt.Printf("\n***** %s *****\n\n", name)
	e.Encode(i)
}
