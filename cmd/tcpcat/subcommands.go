package main

// subcommands maps `tcpcat <name> ...` to its handler. A handler receives
// the arguments after the name and returns the process exit status.
var subcommands = map[string]func([]string) int{
	"policy":    runPolicy,
	"evidence":  runEvidence,
	"replay":    runReplay,
	"inventory": runInventory,
	"explain":   runExplain,
}

// isHelpRequest: usage text is printed without the banner, so it reads as
// plain help (and pipes cleanly into a pager).
func isHelpRequest(args []string) bool {
	if len(args) == 0 {
		return false // `tcpcat inventory` alone is a real run
	}
	switch args[0] {
	case "-h", "--help", "help":
		return true
	}
	return false
}
