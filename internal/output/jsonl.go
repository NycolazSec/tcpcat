package output

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"tcpcat/internal/scan"
)

type AuditRecord struct {
	Timestamp time.Time           `json:"timestamp"`
	ScanID    string              `json:"scan_id"`
	Target    string              `json:"target"`
	Duration  string              `json:"duration"`
	Options   AuditOptions        `json:"options"`
	Results   []scan.TargetResult `json:"results"`
}

type AuditOptions struct {
	Profile   string `json:"profile,omitempty"`
	ScopeFile string `json:"scope_file,omitempty"`
	Ports     string `json:"ports,omitempty"`
	TopPorts  int    `json:"top_ports,omitempty"`
	Timing    int    `json:"timing"`
	RateLimit int    `json:"rate_limit"`
}

func ExportAuditJSONL(filePath, target string, options AuditOptions, results []scan.TargetResult, duration time.Duration) error {
	randomID := make([]byte, 16)
	if _, err := rand.Read(randomID); err != nil {
		return fmt.Errorf("generate audit scan ID: %w", err)
	}

	record := AuditRecord{
		Timestamp: time.Now().UTC(),
		ScanID:    hex.EncodeToString(randomID),
		Target:    target,
		Duration:  duration.Round(time.Millisecond).String(),
		Options:   options,
		Results:   results,
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("serialize audit record: %w", err)
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	return nil
}
