package evasion

type Config struct {
	SourcePort int
	TTL        int
	Payload    []byte
	Proxy      *ProxyConfig
	Spoof      *SpoofConfig
	Decoys     *DecoyConfig
}

func NewConfig(sourcePort int, ttl int, dataStr string, dataHex string, proxyStr string, decoyStr string) (*Config, error) {
	cfg := &Config{
		SourcePort: sourcePort,
		TTL:        ttl,
	}

	payload, err := PreparePayload(dataStr, dataHex)
	if err != nil {
		return nil, err
	}
	cfg.Payload = payload

	pCfg, err := ParseProxyURL(proxyStr)
	if err != nil {
		return nil, err
	}
	cfg.Proxy = pCfg

	cfg.Spoof = &SpoofConfig{}

	decoys, err := ParseDecoys(decoyStr)
	if err != nil && decoyStr != "" {
		return nil, err
	}
	cfg.Decoys = &DecoyConfig{
		DecoyIPs: decoys,
		Enabled:  len(decoys) > 0,
	}

	return cfg, nil
}
