package cli

import (
	"fmt"
	"path/filepath"

	"github.com/benakaben10/secret-mask/internal/version"
)

// InstallerURL is the one-line installer, which also upgrades.
const InstallerURL = "https://raw.githubusercontent.com/benakaben10/secret-mask/master/install.sh"

// upgrade prints how to upgrade this installation. Like the release archives, the binary makes no network
// request itself: the installer downloads, verifies the checksum and swaps the binary.
func (a *App) upgrade(args []string) error {
	fs := a.flagSet("upgrade")
	tag := fs.String("version", "", "release tag to install, e.g. v0.3.0 (default: latest)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	exe, err := a.Executable()
	if err != nil {
		return err
	}
	opts := " --dir " + shellQuote(filepath.Dir(exe))
	if *tag != "" {
		opts += " --version " + shellQuote(*tag)
	}
	fmt.Fprintf(a.Stdout, "Installed: secret-mask %s at %s\n\n", version.Version, exe)
	fmt.Fprintf(a.Stdout, "Upgrade in place (checks SHA256SUMS, keeps this path so agent configs and git hooks keep working,\nrefreshes the agent configuration):\n")
	fmt.Fprintf(a.Stdout, "  curl -fsSL %s | sh -s --%s\n\n", InstallerURL, opts)
	fmt.Fprintln(a.Stdout, "Other installs:")
	fmt.Fprintln(a.Stdout, "  Go:      go install github.com/benakaben10/secret-mask/cmd/secret-mask@latest && secret-mask install")
	fmt.Fprintln(a.Stdout, "  Docker:  docker pull ghcr.io/benakaben10/secret-mask:latest")
	fmt.Fprintln(a.Stdout, "  Plugin:  claude plugin marketplace update secret-mask && claude plugin update secret-mask@secret-mask")
	return nil
}
