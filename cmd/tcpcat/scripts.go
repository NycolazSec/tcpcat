package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/scripthub"
)

const scriptsUsage = `Manage tcpcat's WebAssembly detection modules (dissectors) from a hub.

  tcpcat scripts search [query]     find dissectors in the hub index
  tcpcat scripts info <name>        show a dissector's details
  tcpcat scripts install <name>...  download + verify (SHA-256) into the scripts dir
  tcpcat scripts list               list installed modules
  tcpcat scripts remove <name>...   delete installed modules
  tcpcat scripts dir                print the scripts directory

Use the installed modules in a scan:

  tcpcat -sV -p 6379 --scripts "$(tcpcat scripts dir)" <target>

Options (per command):
  --index <url|path>   hub index to use (default: the community hub, or
                       $TCPCAT_SCRIPTS_INDEX)
  --json               machine-readable output (search, info, list)
`

// runScripts dispatches `tcpcat scripts <action>`.
func runScripts(args []string) int {
	if len(args) == 0 {
		fmt.Print(scriptsUsage)
		return 2
	}
	action, rest := args[0], args[1:]
	switch action {
	case "search":
		return scriptsSearch(rest)
	case "info":
		return scriptsInfo(rest)
	case "install", "add":
		return scriptsInstall(rest)
	case "list", "ls":
		return scriptsList(rest)
	case "remove", "rm", "uninstall":
		return scriptsRemove(rest)
	case "dir":
		fmt.Println(mustScriptsDir())
		return 0
	case "-h", "--help", "help":
		fmt.Print(scriptsUsage)
		return 0
	default:
		fmt.Printf("%s[!] Unknown scripts command %q.%s\n\n", config.Red, action, config.Reset)
		fmt.Print(scriptsUsage)
		return 2
	}
}

func scriptsFlags(name string) (*flag.FlagSet, *string, *bool) {
	fs := flag.NewFlagSet("scripts "+name, flag.ContinueOnError)
	index := fs.String("index", "", "hub index URL or path")
	asJSON := fs.Bool("json", false, "machine-readable output")
	return fs, index, asJSON
}

func scriptsSearch(args []string) int {
	fs, index, asJSON := scriptsFlags("search")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	idx, _, err := scripthub.FetchIndex(scripthub.IndexSource(*index))
	if err != nil {
		return scriptsErr(err)
	}
	query := ""
	if fs.NArg() > 0 {
		query = fs.Arg(0)
	}
	results := idx.Search(query)
	if *asJSON {
		return emitJSON(results)
	}
	if len(results) == 0 {
		fmt.Printf("%s[~] No dissectors match %q.%s\n", config.White, query, config.Reset)
		return 0
	}
	for _, d := range results {
		fmt.Printf("%s%-16s%s %s%-8s%s %s\n",
			config.Bold, d.Name, config.Reset,
			config.Gray, d.Version, config.Reset, d.Description)
	}
	return 0
}

func scriptsInfo(args []string) int {
	fs, index, asJSON := scriptsFlags("info")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Printf("%s[!] Usage: tcpcat scripts info <name>%s\n", config.Red, config.Reset)
		return 2
	}
	idx, _, err := scripthub.FetchIndex(scripthub.IndexSource(*index))
	if err != nil {
		return scriptsErr(err)
	}
	d, ok := idx.Find(fs.Arg(0))
	if !ok {
		fmt.Printf("%s[!] %q is not in the hub index.%s\n", config.Red, fs.Arg(0), config.Reset)
		return 1
	}
	if *asJSON {
		return emitJSON(d)
	}
	fmt.Printf("%s%s%s %s\n", config.Bold, d.Name, config.Reset, d.Version)
	fmt.Printf("  %s\n", d.Description)
	if d.Author != "" {
		fmt.Printf("  author:  %s\n", d.Author)
	}
	if d.License != "" {
		fmt.Printf("  license: %s\n", d.License)
	}
	if len(d.Ports) > 0 {
		fmt.Printf("  ports:   %v\n", d.Ports)
	}
	if d.Homepage != "" {
		fmt.Printf("  home:    %s\n", d.Homepage)
	}
	fmt.Printf("  %ssha256:  %s%s\n", config.Gray, d.SHA256, config.Reset)
	return 0
}

func scriptsInstall(args []string) int {
	fs, index, _ := scriptsFlags("install")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Printf("%s[!] Usage: tcpcat scripts install <name>...%s\n", config.Red, config.Reset)
		return 2
	}
	idx, base, err := scripthub.FetchIndex(scripthub.IndexSource(*index))
	if err != nil {
		return scriptsErr(err)
	}
	dir := mustScriptsDir()
	rc := 0
	for _, name := range fs.Args() {
		d, ok := idx.Find(name)
		if !ok {
			fmt.Printf("%s[!] %q is not in the hub index.%s\n", config.Red, name, config.Reset)
			rc = 1
			continue
		}
		path, err := scripthub.Install(d, base, dir)
		if err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			rc = 1
			continue
		}
		fmt.Printf("%s[+] installed %s %s%s%s -> %s\n",
			config.White, d.Name, config.Gray, d.Version, config.Reset, path)
	}
	if rc == 0 {
		fmt.Printf("%s[i] use them:%s tcpcat -sV --scripts %q <target>\n", config.Gray, config.Reset, dir)
	}
	return rc
}

func scriptsList(args []string) int {
	fs, _, asJSON := scriptsFlags("list")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir := mustScriptsDir()
	installed, err := scripthub.Installed(dir)
	if err != nil {
		return scriptsErr(err)
	}
	if *asJSON {
		return emitJSON(installed)
	}
	if len(installed) == 0 {
		fmt.Printf("%s[~] No modules installed. Try: tcpcat scripts search%s\n", config.White, config.Reset)
		return 0
	}
	for _, s := range installed {
		fmt.Printf("%s%-16s%s %s%s  %d bytes%s\n",
			config.Bold, s.Name, config.Reset, config.Gray, s.SHA256[:12], s.Size, config.Reset)
	}
	fmt.Printf("%s[i] dir: %s%s\n", config.Gray, dir, config.Reset)
	return 0
}

func scriptsRemove(args []string) int {
	fs, _, _ := scriptsFlags("remove")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Printf("%s[!] Usage: tcpcat scripts remove <name>...%s\n", config.Red, config.Reset)
		return 2
	}
	dir := mustScriptsDir()
	rc := 0
	for _, name := range fs.Args() {
		if err := scripthub.Remove(name, dir); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			rc = 1
			continue
		}
		fmt.Printf("%s[-] removed %s%s\n", config.White, name, config.Reset)
	}
	return rc
}

func mustScriptsDir() string {
	dir, err := scripthub.ScriptsDir()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
		os.Exit(1)
	}
	return dir
}

func scriptsErr(err error) int {
	fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
	return 1
}

func emitJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return scriptsErr(err)
	}
	return 0
}
