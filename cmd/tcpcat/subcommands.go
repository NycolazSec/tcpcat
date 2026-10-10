package main

// subcommands maps `tcpcat <name> ...` to its handler. A handler receives
// the arguments after the name and returns the process exit status.
var subcommands = map[string]func([]string) int{
	"policy":   runPolicy,
	"evidence": runEvidence,
	"replay":   runReplay,
}
