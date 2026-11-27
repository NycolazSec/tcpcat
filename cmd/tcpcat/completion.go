package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/NycolazSec/tcpcat/config"
)

func runCompletion(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: tcpcat completion <bash|zsh|fish>")
		return exitError
	}

	script, err := completionScript(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}
	fmt.Print(script)
	return exitOK
}

func completionScript(shell string) (string, error) {
	candidates := completionCandidates()
	words := strings.Join(candidates, " ")

	switch shell {
	case "bash":
		return fmt.Sprintf(`_tcpcat_completion() {
  local current="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W %q -- "$current") )
}
complete -F _tcpcat_completion tcpcat
`, words), nil
	case "zsh":
		return fmt.Sprintf(`#compdef tcpcat

_tcpcat() {
  local -a candidates=( %s )
  compadd -- "${candidates[@]}"
}

compdef _tcpcat tcpcat
`, words), nil
	case "fish":
		return fmt.Sprintf("complete -c tcpcat -f -a '%s'\n", words), nil
	default:
		return "", fmt.Errorf("unsupported shell %q (expected bash, zsh, or fish)", shell)
	}
}

func completionCandidates() []string {
	fs := flag.NewFlagSet("tcpcat completion", flag.ContinueOnError)
	config.DefineFlags(fs, &config.Options{})

	var candidates []string
	fs.VisitAll(func(f *flag.Flag) {
		candidates = append(candidates, "-"+f.Name, "--"+f.Name)
	})
	for name := range subcommands {
		candidates = append(candidates, name)
	}
	sort.Strings(candidates)
	return candidates
}
