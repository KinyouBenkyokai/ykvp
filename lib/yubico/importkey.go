package yubico

import "os/exec"

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
