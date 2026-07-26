package vuln

type Vulnerability struct {
	ID    string  `json:"id"`
	Title string  `json:"title"`
	CVSS  float64 `json:"cvss"`
}

type Scanner interface {
	GetForSoftware(software, version string) ([]Vulnerability, error)
	SourceName() string
}
