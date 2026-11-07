package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// PromptPassword reads a password from the controlling terminal with echo off. With confirm it asks
// twice and fails on a mismatch.
func PromptPassword(confirm bool) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no password: set $%s or run in a terminal", DefaultPasswordEnv)
	}
	defer tty.Close()
	r := bufio.NewReader(tty)
	read := func(prompt string) (string, error) {
		fmt.Fprint(tty, prompt)
		stty(tty, "-echo")
		line, err := r.ReadString('\n')
		stty(tty, "echo")
		fmt.Fprintln(tty)
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	pw, err := read("Password: ")
	if err != nil {
		return "", err
	}
	if confirm {
		again, err := read("Confirm password: ")
		if err != nil {
			return "", err
		}
		if again != pw {
			return "", &UsageError{"passwords do not match"}
		}
	}
	return pw, nil
}

func stty(tty *os.File, arg string) {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = tty
	_ = cmd.Run()
}
