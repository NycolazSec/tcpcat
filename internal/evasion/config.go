// internal/evasion/config.go
package evasion

type Config struct {
	SourcePort int
	TTL        int
	Payload    []byte
	Proxy      *ProxyConfig
	Spoof      *SpoofConfig
	Decoys     *DecoyConfig
}

// NewConfig initialise la configuration d'évasion avancée.
func NewConfig(sourcePort int, ttl int, dataStr string, dataHex string, proxyStr string) (*Config, error) {
	cfg := &Config{
		SourcePort: sourcePort,
		TTL:        ttl,
	}

	// 1. Payload
	payload, err := PreparePayload(dataStr, dataHex)
	if err != nil {
		return nil, err
	}
	cfg.Payload = payload

	// 2. Proxy
	pCfg, err := ParseProxyURL(proxyStr)
	if err != nil {
		return nil, err
	}
	cfg.Proxy = pCfg

	// 3. Spoof & Decoys (Initialisés vides car non fonctionnels via net.Dial)
	cfg.Spoof = &SpoofConfig{}
	cfg.Decoys = &DecoyConfig{}

	return cfg, nil
}