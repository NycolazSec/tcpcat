package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"tcpcat/internal/scan"
)

func ExportScriptKiddie(filePath string, target string, results []scan.TargetResult, duration time.Duration) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("impossible de créer le fichier %s: %w", filePath, err)
	}
	defer file.Close()

	rawText := fmt.Sprintf("tcpcat scan report for %s\nCompleted in %v\n\n", target, duration.Round(time.Millisecond))
	for _, r := range results {
		rawText += fmt.Sprintf("Port %d/tcp is %s (%s)\n", r.Port, r.State, r.Service)
	}

	leetText := toLeet(rawText)
	_, err = file.WriteString(leetText)
	return err
}

func toLeet(s string) string {
	replacer := strings.NewReplacer(
		"a", "4", "A", "4",
		"e", "3", "E", "3",
		"i", "1", "I", "1",
		"o", "0", "O", "0",
		"s", "5", "S", "5",
		"t", "7", "T", "7",
	)
	return replacer.Replace(s)
}
