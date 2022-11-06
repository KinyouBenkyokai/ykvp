package entity

import (
	"encoding/json"
	"github.com/kinyoubenkyokai/yuberify/lib"
	"time"
)

type Claim struct {
	Age            int    `json:"age"`
	UniversityName string `json:"universityName"`
	Degree         string `json:"degree"`
}

type CredentialSubject struct {
	ID    []byte `json:"id"`
	Claim Claim  `json:"claim"`
}

type CredentialToSign struct {
	Context           []string          `json:"context"`
	TypeOfCredential  []string          `json:"type"`
	IssuanceDate      time.Time         `json:"issuanceDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
}

type Credential struct {
	CredentialToSign

	Proof Proof `json:"proof"`
}

func UnmarshalCredential(b []byte) (*CredentialToSign, error) {
	var res CredentialToSign
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c Claim) GetType() []string {
	return []string{"GraduationCredential"}
}

func (c Credential) Export() (buf []byte, err error) {
	buf, err = lib.Export(c.CredentialToSign)
	return buf, err
}
