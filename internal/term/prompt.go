// Package term provides console prompts that do not echo secrets.
package term

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ReadLine prompts and reads one visible line.
func ReadLine(prompt string) (string, error) {
	fmt.Print(prompt)
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return "", sc.Err()
	}
	return strings.TrimSpace(sc.Text()), nil
}

// ReadSecret prompts and reads one line without echoing it.
func ReadSecret(prompt string) (string, error) {
	fmt.Print(prompt)
	var out string
	err := withEchoDisabled(func() error {
		sc := bufio.NewScanner(os.Stdin)
		if !sc.Scan() {
			return sc.Err()
		}
		out = sc.Text()
		return nil
	})
	fmt.Println()
	return out, err
}

// ReadSecretConfirmed prompts twice and requires the entries to match.
func ReadSecretConfirmed(label string) (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		a, err := ReadSecret(label + ": ")
		if err != nil {
			return "", err
		}
		if len(a) < 8 {
			fmt.Println("     SNMPv3 requires at least 8 characters; try again.")
			continue
		}
		b, err := ReadSecret(label + " (confirm): ")
		if err != nil {
			return "", err
		}
		if a != b {
			fmt.Println("     Entries did not match; try again.")
			continue
		}
		return a, nil
	}
	return "", fmt.Errorf("term: %s not confirmed after 3 attempts", label)
}
