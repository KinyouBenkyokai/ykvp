package yubico

import (
	"fmt"
	"os/exec"
)

func RunCmd(cmd exec.Cmd, stdin []byte) ([]byte, error) {
	fd0Pipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}
	if _, err := fd0Pipe.Write(stdin); err != nil {
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
