package main

import (
	"fmt"
	"github.com/NycolazSec/tcpcat/internal/output"
	"github.com/NycolazSec/tcpcat/internal/scan"
)

func main() {
	err := output.ExportSARIF("/tmp/out.sarif", []scan.TargetResult{
		{IP: "1.2.3.4", Port: 22, State: scan.StateClosed},
	}, nil)
	fmt.Println(err)
}
