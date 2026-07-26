package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func Run(target map[string]interface{}) map[string]string {
	output := make(map[string]string)

	ip, okIP := target["IP"].(string)
	port, okPort := target["Port"].(int)

	if !okIP || !okPort {
		return output
	}

	if port != 80 && port != 443 && port != 8080 {
		return output
	}

	protocol := "http"
	if port == 443 {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s:%d", protocol, ip, port)

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return output
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return output
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if err != nil {
		return output
	}

	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(string(body))

	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		if title != "" {
			output["http_title"] = title
		}
	}

	return output
}
