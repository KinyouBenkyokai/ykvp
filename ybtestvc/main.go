package main

import (
	"fmt"
	"os/exec"
)

func main() {
	// set data text
	out, err := verify("aaa")
	if err != nil {
		panic(err)
	}
	fmt.Println(out)
}

func verify(text string) ([]byte, error) {
	cmd := exec.Command("yubico-piv-tool", "-a", "verify-pin", "--sign", "-s", "9c", "-H", "SHA512", "-A", "RSA2048", "-P", "123456")
	fd0Pipe, _ := cmd.StdinPipe()

	if _, err := fd0Pipe.Write([]byte(text)); err != nil {
		return nil, err
	}
	if err := fd0Pipe.Close(); err != nil {
		return nil, err
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}
