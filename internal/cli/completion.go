package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/benakaben10/secret-mask/internal/detect"
	"github.com/benakaben10/secret-mask/internal/hook"
	"github.com/benakaben10/secret-mask/internal/setup"
)

// completionFlag is a flag and what its value completes to: "" (no value), "file", "dir", "text", or a
// space-separated list of choices.
type completionFlag struct{ name, value, help string }

type completionCmd struct {
	name, help string
	arg        string // positional argument: "dir", "path" or ""
	flags      []completionFlag
}

// completionCommands mirrors the commands and their flags; a test checks it against every flag set.
func completionCommands() []completionCmd {
	target := []completionFlag{
		{"vault", "file", "vault file"}, {"guide", "file", "AI guide file"},
		{"password-env", "text", "variable holding the password"}, {"ask", "", "prompt for the password"},
	}
	config := completionFlag{"config", "file", "gitleaks config"}
	clients := strings.Join(setup.ClientIDs(), " ")
	return []completionCmd{
		{"mask", "mask the detected secrets", "dir", append(target, config,
			completionFlag{"report", "file", "gitleaks JSON report"}, completionFlag{"dry-run", "", "show without writing"})},
		{"restore", "put the real values back (unseal)", "dir", append(target,
			completionFlag{"force", "", "restore what is present"}, completionFlag{"dry-run", "", "show without writing"},
			completionFlag{"clean", "", "delete the vault and guide"})},
		{"status", "are all placeholders present", "dir", target},
		{"reveal", "show the real values and where they are (your terminal only)", "dir", []completionFlag{
			{"vault", "file", "vault file"}, {"id", "text", "one placeholder"}, {"file", "file", "only this file"}}},
		{"check", "fail if unmasked secrets", "path", []completionFlag{config, {"root", "dir", "project root"}}},
		{"rules", "list the detection rules", "dir", []completionFlag{config, {"id", "text", "one rule in full"},
			{"source", strings.Join([]string{detect.SourceGitleaks, detect.SourceSecretMask, detect.SourceProject}, " "), "rule source"},
			{"json", "", "JSON output"}}},
		{"install", "set up the coding agents", "", []completionFlag{{"clients", clients, "agents"},
			{"command", "text", "command written into configs"}, {"no-hooks", "", "no read-blocking hooks"},
			{"dry-run", "", "show without writing"}, {"force", "", "replace foreign files"}}},
		{"uninstall", "remove the agent setup", "", []completionFlag{{"clients", clients, "agents"}, {"dry-run", "", "show without writing"}}},
		{"protect", "git pre-commit hook", "dir", []completionFlag{{"mode", "block mask", "block or mask"},
			{"command", "text", "command the hook runs"}, {"remove", "", "remove the hook"}}},
		{"setup", "Claude Code setup for one project", "dir", []completionFlag{{"scope", "project user", "scope"},
			{"command", "text", "command written into configs"}}},
		{"upgrade", "how to upgrade to a new release", "", []completionFlag{{"version", "text", "release tag"}}},
		{"completion", "shell completion", "", []completionFlag{{"install", "", "add it to the shell startup file"},
			{"uninstall", "", "remove it from the shell startup file"}}},
		{"pre-commit", "the pre-commit check", "", []completionFlag{{"mode", "block mask", "block or mask"}, config}},
		{"hook", "agent pre-tool hook (stdin)", "", []completionFlag{{"client", strings.Join(hook.Clients, " "), "hook format"}, config}},
		{"mcp", "MCP server on stdio", "", []completionFlag{{"dir", "dir", "project root"}, config}},
		{"version", "print the version", "", nil},
		{"help", "show usage", "", nil},
	}
}

var completionShells = []string{"bash", "zsh"}

// completion prints a completion script, or adds/removes it in the shell's startup file.
func (a *App) completion(args []string) error {
	fs := a.flagSet("completion")
	install := fs.Bool("install", false, "load the completion from ~/.bashrc or ~/.zshrc")
	uninstall := fs.Bool("uninstall", false, "remove it from ~/.bashrc or ~/.zshrc")
	shell, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if shell == "." {
		shell = filepath.Base(a.Getenv("SHELL"))
	}
	if shell != "bash" && shell != "zsh" {
		return &UsageError{fmt.Sprintf("unknown shell %q: use bash or zsh", shell)}
	}
	if !*install && !*uninstall {
		if shell == "bash" {
			fmt.Fprint(a.Stdout, bashCompletion())
		} else {
			fmt.Fprint(a.Stdout, zshCompletion())
		}
		return nil
	}
	home, _ := os.UserHomeDir()
	if h := a.Getenv("HOME"); h != "" {
		home = h
	}
	rc := filepath.Join(home, "."+shell+"rc")
	exe, err := a.Executable()
	if err != nil {
		exe = "secret-mask"
	}
	body := fmt.Sprintf("# shell completion for secret-mask (remove with: secret-mask completion --uninstall %s)\n", shell)
	if shell == "zsh" {
		body += "autoload -Uz compinit && (( $+functions[compdef] )) || compinit\n"
	}
	body += fmt.Sprintf("if [ -x %[1]s ]; then eval \"$(%[1]s completion %[2]s)\"; fi\n", shellQuote(exe), shell)
	if *uninstall {
		body = ""
	}
	status, err := setup.ManagedBlock(rc, "# >>> secret-mask completion >>>", "# <<< secret-mask completion <<<", body)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "%s (%s)\n", rc, status)
	if *install && status != "unchanged" {
		fmt.Fprintf(a.Stdout, "Open a new shell, or run: source %s\n", rc)
	}
	return nil
}

func bashCompletion() string {
	var b strings.Builder
	b.WriteString("# bash completion for secret-mask. Load it with: eval \"$(secret-mask completion bash)\"\n")
	b.WriteString("_secret_mask() {\n  local cur prev cmd\n  cur=${COMP_WORDS[COMP_CWORD]}\n  prev=${COMP_WORDS[COMP_CWORD-1]}\n  cmd=${COMP_WORDS[1]}\n")
	var names []string
	for _, c := range completionCommands() {
		names = append(names, c.name)
	}
	fmt.Fprintf(&b, "  if [ \"$COMP_CWORD\" -eq 1 ]; then\n    COMPREPLY=($(compgen -W %q -- \"$cur\"))\n    return\n  fi\n", strings.Join(names, " "))
	b.WriteString("  case \"$cmd:$prev\" in\n")
	for _, c := range completionCommands() {
		for _, f := range c.flags {
			pattern := fmt.Sprintf("%[1]s:-%[2]s|%[1]s:--%[2]s", c.name, f.name)
			switch f.value {
			case "":
			case "file":
				fmt.Fprintf(&b, "    %s) COMPREPLY=($(compgen -f -- \"$cur\")); return ;;\n", pattern)
			case "dir":
				fmt.Fprintf(&b, "    %s) COMPREPLY=($(compgen -d -- \"$cur\")); return ;;\n", pattern)
			case "text":
				fmt.Fprintf(&b, "    %s) return ;;\n", pattern)
			default:
				fmt.Fprintf(&b, "    %s) COMPREPLY=($(compgen -W %q -- \"${cur##*,}\")); return ;;\n", pattern, f.value)
			}
		}
	}
	b.WriteString("  esac\n  case \"$cmd\" in\n")
	for _, c := range completionCommands() {
		var flags []string
		for _, f := range c.flags {
			flags = append(flags, "--"+f.name)
		}
		args := ""
		switch c.arg {
		case "dir":
			args = `$(compgen -d -- "$cur")`
		case "path":
			args = `$(compgen -f -- "$cur")`
		}
		if c.name == "completion" {
			args = `$(compgen -W "bash zsh" -- "$cur")`
		}
		fmt.Fprintf(&b, "    %s)\n      if [[ $cur == -* ]]; then COMPREPLY=($(compgen -W %q -- \"$cur\")); else COMPREPLY=(%s); fi ;;\n",
			c.name, strings.Join(flags, " "), args)
	}
	b.WriteString("  esac\n}\ncomplete -o filenames -F _secret_mask secret-mask\n")
	return b.String()
}

func zshCompletion() string {
	var b strings.Builder
	b.WriteString("#compdef secret-mask\n# zsh completion for secret-mask. Load it with: eval \"$(secret-mask completion zsh)\" (after compinit)\n")
	b.WriteString("_secret_mask() {\n  local -a commands\n  commands=(\n")
	for _, c := range completionCommands() {
		fmt.Fprintf(&b, "    %s\n", zshQuote(c.name+":"+c.help))
	}
	b.WriteString("  )\n  local curcontext=$curcontext state line\n  _arguments -C '1: :->cmd' '*:: :->args'\n")
	b.WriteString("  case $state in\n    cmd) _describe -t commands 'secret-mask command' commands ;;\n    args)\n      case $words[1] in\n")
	for _, c := range completionCommands() {
		specs := []string{}
		for _, f := range c.flags {
			action := ""
			switch f.value {
			case "":
			case "file":
				action = ":file:_files"
			case "dir":
				action = ":directory:_files -/"
			case "text":
				action = ":" + f.name + ": "
			default:
				action = ":" + f.name + ":(" + f.value + ")"
			}
			help := strings.NewReplacer("[", "(", "]", ")", "'", "").Replace(f.help)
			specs = append(specs, zshQuote("--"+f.name+"["+help+"]"+action))
		}
		switch {
		case c.name == "completion":
			specs = append(specs, zshQuote("1:shell:(bash zsh)"))
		case c.arg == "dir":
			specs = append(specs, zshQuote("1:directory:_files -/"))
		case c.arg == "path":
			specs = append(specs, zshQuote("1:path:_files"))
		}
		fmt.Fprintf(&b, "        %s) _arguments %s ;;\n", c.name, strings.Join(specs, " "))
	}
	b.WriteString("      esac ;;\n  esac\n}\n")
	b.WriteString("if [ \"$funcstack[1]\" = _secret_mask ]; then _secret_mask \"$@\"; else compdef _secret_mask secret-mask; fi\n")
	return b.String()
}

func zshQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
