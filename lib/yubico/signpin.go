package yubico

import (
	"fmt"
	"os/exec"
)

type SignPin struct {
}

func NewSignPin() SignPin {
	return SignPin{}
}

func (s SignPin) VerifyByYubikey(text []byte, pin int32) ([]byte, error) {
	pinstr := fmt.Sprintf("%d", pin)
	cmd := exec.Command("yubico-piv-tool", "-a", "verify-pin", "--sign", "-s", "9c", "-A", "ECCP256", "-P", pinstr)
	return RunCmd(*cmd, text)
}
