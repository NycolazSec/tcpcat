package main

import (
	"flag"
	"strings"
	"testing"

	"github.com/NycolazSec/tcpcat/config"
)

func TestCompletionScriptsContainEveryFlagAndSubcommand(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	config.DefineFlags(fs, &config.Options{})

	scripts := []string{"bash", "zsh", "fish"}
	for _, shell := range scripts {
		t.Run(shell, func(t *testing.T) {
			script, err := completionScript(shell)
			if err != nil {
				t.Fatal(err)
			}

			fs.VisitAll(func(f *flag.Flag) {
				for _, option := range []string{"-" + f.Name, "--" + f.Name} {
					if !strings.Contains(script, option) {
						t.Errorf("%s completion is missing option %q", shell, option)
					}
				}
			})
			for name := range subcommands {
				if !strings.Contains(script, name) {
					t.Errorf("%s completion is missing subcommand %q", shell, name)
				}
			}
		})
	}
}

func TestCompletionScriptRejectsUnknownShell(t *testing.T) {
	if _, err := completionScript("powershell"); err == nil {
		t.Fatal("completionScript() accepted an unsupported shell")
	}
}
