package vuln

import (
	"math"
	"strings"
)

var weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0.0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0.0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0.0},
}

var prWeights = map[string]map[string]float64{
	"U": {"N": 0.85, "L": 0.62, "H": 0.27},
	"C": {"N": 0.85, "L": 0.68, "H": 0.50},
}

func roundup(f float64) float64 {
	return math.Ceil(f*10) / 10
}

func ParseAndCalculateCVSSv3(vector string) float64 {
	metrics := make(map[string]string)
	parts := strings.Split(vector, "/")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	av := weights["AV"][metrics["AV"]]
	ac := weights["AC"][metrics["AC"]]
	ui := weights["UI"][metrics["UI"]]
	c := weights["C"][metrics["C"]]
	i := weights["I"][metrics["I"]]
	a := weights["A"][metrics["A"]]
	s := metrics["S"]
	if s == "" {
		s = "U"
	}
	pr := prWeights[s][metrics["PR"]]

	exploitability := 8.22 * av * ac * pr * ui

	impactSubScore := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impact float64
	if s == "U" {
		impact = 6.42 * impactSubScore
	} else {
		impact = 7.52*(impactSubScore-0.029) - 3.25*math.Pow(impactSubScore-0.02, 15)
	}

	if impact <= 0 {
		return 0.0
	}

	var baseScore float64
	if s == "U" {
		baseScore = math.Min(impact+exploitability, 10)
	} else {
		baseScore = math.Min(1.08*(impact+exploitability), 10)
	}

	return roundup(baseScore)
}
