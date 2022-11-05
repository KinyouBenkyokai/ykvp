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
	fd0Pipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}
	if _, err := fd0Pipe.Write(text); err != nil {
		return nil, fmt.Errorf("failed to write to stdin pipe: %w", err)
	}
	if err := fd0Pipe.Close(); err != nil {
		return nil, fmt.Errorf("failed to close stdin pipe: %w", err)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}
	return out, nil
}
