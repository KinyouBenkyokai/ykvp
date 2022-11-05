package main

import (
	"fmt"
	"os/exec"
)

func main() {
	cmd := exec.Command("yubico-piv-tool", "-a", "verify-pin", "--sign", "-s", "9c", "-H", "SHA512", "-A", "RSA2048", "-i", "data.txt", "-o", "data.sig", "-P", "123456")
	out, err := cmd.CombinedOutput()
	fmt.Println(string(out))
	if err != nil {
		panic(err)
	}
}
