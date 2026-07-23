// internal/evasion/proxy.go
package evasion

import (
	"fmt"
	"net/url"
)

type ProxyConfig struct {
	URL      *url.URL
	Enabled  bool
}

// ParseProxyURL valide et parse l'URL du proxy (ex: socks5://127.0.0.1:9050).
func ParseProxyURL(proxyStr string) (*ProxyConfig, error) {
	if proxyStr == "" {
		return &ProxyConfig{Enabled: false}, nil
	}

	u, err := url.Parse(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	// Validation basique du schéma supporté
	if u.Scheme != "socks5" && u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported proxy scheme '%s'. Only 'socks5' or 'http' are implemented", u.Scheme)
	}

	return &ProxyConfig{URL: u, Enabled: true}, nil
}