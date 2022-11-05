package entity

import (
	"github.com/kinyoubenkyokai/yuberify/lib"
)

type PresentationToSign struct {
	Context            []string   `json:"context"`
	TypeOfPresentation []string   `json:"type"`
	Credential         Credential `json:"credential"`
	Nonce              []byte     `json:"nonce"`
}

type Presentation struct {
	PresentationToSign

	Proof Proof `json:"proof"`
}

func (p Presentation) Export() (buf []byte, err error) {
	buf, err = lib.Export(p.PresentationToSign)
	return buf, err
}
