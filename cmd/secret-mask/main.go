// Command secret-mask replaces secrets found by gitleaks with placeholders and keeps the originals in a
// password-encrypted vault, so a tree can be shared (for example with AI tools) and restored exactly.
package main

import (
	"os"

	"github.com/benakaben10/secret-mask/internal/cli"
)

func main() {
	os.Exit(cli.New().Run(os.Args[1:]))
}
