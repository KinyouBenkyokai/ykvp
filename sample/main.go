package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
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

func generatePKCS12FileAndImportToYubikey() (*ecdsa.PublicKey, error) {
	//gk := key.NewGenerateKey()
	//prv, _ := gk.GenerateECDSAPrivateKey()
	//pub := gk.GetPublicKeyFromECDSAPrivateKey(prv)
	//prvPEM, err := gk.CreateX509FromECDSAPrivateKey(prv)
	//if err != nil {
	//	return nil, err
	//}
	//fmt.Println(prvPEM)
	//cert, err := gk.GenerateCert(pub, prv, key.SetCreateFiles("./tmp/cert.pem"))
	//if err != nil {
	//	return nil, err
	//}
	//pkcs12, err := gk.GeneratePKCS12(cert, prv, "password", key.SetCreateFiles("./tmp/pkcs12.p12"))
	//if err != nil {
	//	return nil, err
	//}
	//fmt.Println(pkcs12)

	yk, err := yubico.NewYubikey()
	if err != nil {
		return nil, err
	}
	defer yk.Close()
	pub, err := yk.ImportKey()
	if err != nil {
		return nil, err
	}

	return pub.(*ecdsa.PublicKey), nil
}
func main() {
	holderPubkey, err := generatePKCS12FileAndImportToYubikey()
	if err != nil {
		panic(err)
	}
	issuer, subject, err := part1(holderPubkey)
	if err != nil {
		panic(err)
	}
	// Part II: The Issuer issues credentials on the Subject.
	credentials, err := part2(issuer, subject)
	if err != nil {
		panic(err)
	}

	// Part III: The Verifier (any third party) can check the claim of the
	// Subject that it holds the credentials
	verifier := verifier.CreateVerifier()
	if err := part3(subject, verifier, credentials, holderPubkey); err != nil {
		panic(err)
	}
}

func part1(pub *ecdsa.PublicKey) (issuer.Issuer, holder.Subject, error) {
	// Part I: Create the issuer, the subject, and the verifier.
	issuer, err := issuer.CreateIssuer(issuerID, issuerName)
	if err != nil {
		panic(err)
	}

	subject, err := holder.CreateSubject(pub)
	if err != nil {
		return issuer, subject, err
	}
	return issuer, subject, err
}

func part2(issuer issuer.Issuer, subject holder.Subject) (entity.Credential, error) {
	// Step 1: Create a Subject and a claim to sign about this subject.
	// The claim is created jointly by the Subject and the Issuer. How they come
	// to agree on the claim to sign is out of scope here.
	claim := entity.Claim{
		Age:            24,
		UniversityName: "Oxford",
		Degree:         "Bachelor of Science",
	}
	nicePrint(claim, "Claim")

	// Step 2: The Issuer signs the claim about this subject.
	id, err := subject.GetID()
	if err != nil {
		return entity.Credential{}, err
	}
	credentials, err := issuer.SignCredential(claim, id)
	if err != nil {
		err = fmt.Errorf("Issuer couldn't sign credentials: %w", err)
		return credentials, err
	}

	nicePrint(credentials, "Credential")
	return credentials, err
}

func part3(subject holder.Subject, verifier verifier.Verifier, credentials entity.Credential, holderPubkey *ecdsa.PublicKey) error {
	// Step 1: The verifier creates a challenge/nonce to be included in the
	// presentation which will be signed bby the subject.
	nonce, err := verifier.MakeNonce()
	if err != nil {
		return err
	}

	// Step 2: The subject creates the presentation and signs it.
	presentation, err := subject.SignPresentation(
		credentials,
		nonce,
		123456,
	)
	if err != nil {
		return err
	}

	nicePrint(presentation, "Presentation")

	// Step 3: The verifier checks that the signature of the presentation is
	// correct.
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
