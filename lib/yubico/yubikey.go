package yubico

import (
	"fmt"
	"os/exec"
)

type Yubikey struct {
}

func NewYubikey() Yubikey {
	return Yubikey{}
}

func (s Yubikey) VerifyByYubikey(text []byte, pin int32) ([]byte, error) {
	pinstr := fmt.Sprintf("%d", pin)
	cmd := exec.Command("yubico-piv-tool",
		"-a", "verify-pin",
		"--sign",
		"-s", "9c",
		"-A", "ECCP256",
		"-P", pinstr,
	)
	return RunCmd(*cmd, text)
}

func ImportKeyToYubikeySlot(pkcsByte []byte, password string) ([]byte, error) {
	cmd := exec.Command("yubico-piv-tool",
		"-s", "9c",
		"-K", "PKCS12",
		"-a", "set-chuid",
		"-a", "import-key",
		"-a", "import-cert",
		"-p", password,
		"-i", "./tmp/pkcs12.p12",
	)
	return RunCmd(*cmd, pkcsByte)
}
