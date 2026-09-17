package main

import (
	"fmt"
	"tcpcat/internal/output"
	"tcpcat/internal/scan"
)

func main() {
	err := output.ExportSARIF("/tmp/out.sarif", []scan.TargetResult{
		{IP: "1.2.3.4", Port: 22, State: scan.StateClosed},
	})
	fmt.Println(err)
}
