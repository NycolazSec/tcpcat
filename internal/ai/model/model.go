package model

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/gob"
	"fmt"
	"math"
	"sort"
)

// Model is a trained classifier. Classes are dictionary IDs ("openssh",
// "redis") plus "other" for banners of services the dictionary lacks.
type Model struct {
	Classes  []string
	LogPrior []float32
	Default  []float32  // log-likelihood of a feature never seen with the class
	Keys     [][]uint32 // per class, sorted feature IDs seen in training
	Values   [][]float32
	// PortKeys/PortValues hold log P(port | class) for the ports each class
	// was seen on, PortDefault the value for any other port. PortWeight
	// scales that term against the banner's: fitted on held-out data.
	PortKeys    [][]int32
	PortValues  [][]float32
	PortDefault []float32
	PortWeight  float32
	Temperature float32 // divides the scores before the softmax; fitted on held-out data
	Trained     string  // provenance, shown by `tcpcat ai model`
}

// Other is the class of banners whose service the dictionary does not know.
const Other = "other"

// Guess is one candidate answer.
type Guess struct {
	ID string  `json:"id"`
	P  float64 `json:"p"`
}

//go:embed weights.bin
var weights []byte

var defaultModel *Model

// Default returns the model embedded in the binary.
func Default() (*Model, error) {
	if defaultModel != nil {
		return defaultModel, nil
	}
	m, err := Decode(weights)
	if err != nil {
		return nil, err
	}
	defaultModel = m
	return m, nil
}

// Classify returns every class with its probability, most likely first.
func (m *Model) Classify(banner string, port int) []Guess {
	feats := Features(banner)
	scores := make([]float64, len(m.Classes))
	best := math.Inf(-1)
	for c := range m.Classes {
		s := float64(m.LogPrior[c])
		keys, vals := m.Keys[c], m.Values[c]
		for _, f := range feats {
			i := sort.Search(len(keys), func(i int) bool { return keys[i] >= f })
			if i < len(keys) && keys[i] == f {
				s += float64(vals[i])
			} else {
				s += float64(m.Default[c])
			}
		}
		if port > 0 {
			pk, pv := m.PortKeys[c], m.PortValues[c]
			i := sort.Search(len(pk), func(i int) bool { return pk[i] >= int32(port) })
			if i < len(pk) && pk[i] == int32(port) {
				s += float64(m.PortWeight) * float64(pv[i])
			} else {
				s += float64(m.PortWeight) * float64(m.PortDefault[c])
			}
		}
		s /= float64(m.Temperature)
		scores[c] = s
		if s > best {
			best = s
		}
	}
	var sum float64
	for c, s := range scores {
		scores[c] = math.Exp(s - best)
		sum += scores[c]
	}
	out := make([]Guess, len(scores))
	for c, s := range scores {
		out[c] = Guess{ID: m.Classes[c], P: s / sum}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].P > out[j].P })
	return out
}

// Encode serializes the model, gzip-compressed.
func (m *Model) Encode() ([]byte, error) {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err := gob.NewEncoder(zw).Encode(m); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode reads a model written by Encode.
func Decode(data []byte) (*Model, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("model: %w", err)
	}
	var m Model
	if err := gob.NewDecoder(zr).Decode(&m); err != nil {
		return nil, fmt.Errorf("model: %w", err)
	}
	if len(m.Classes) == 0 || len(m.LogPrior) != len(m.Classes) || len(m.Keys) != len(m.Classes) ||
		len(m.Values) != len(m.Classes) || len(m.Default) != len(m.Classes) || m.Temperature <= 0 ||
		len(m.PortKeys) != len(m.Classes) || len(m.PortValues) != len(m.Classes) || len(m.PortDefault) != len(m.Classes) {
		return nil, fmt.Errorf("model: inconsistent weights")
	}
	return &m, nil
}

// Example is one labelled banner for training or evaluation.
type Example struct {
	Label  string
	Banner string // as tcpcat stores it
	Port   int
}

// TrainOptions tune training.
type TrainOptions struct {
	Alpha    float64 // additive smoothing
	MinCount int     // features seen fewer times with a class are dropped (smaller model)
}

// Train fits a multinomial naive Bayes model, each feature counted once per
// example. Temperature is left at 1; call Calibrate with held-out data.
func Train(examples []Example, opt TrainOptions) *Model {
	if opt.Alpha <= 0 {
		opt.Alpha = 0.1
	}
	if opt.MinCount < 1 {
		opt.MinCount = 1
	}
	index := map[string]int{}
	var classes []string
	for _, e := range examples {
		if _, ok := index[e.Label]; !ok {
			index[e.Label] = len(classes)
			classes = append(classes, e.Label)
		}
	}
	sort.Strings(classes)
	for i, c := range classes {
		index[c] = i
	}
	docs := make([]float64, len(classes))
	ports := make([]map[int]int, len(classes))
	counts := make([]map[uint32]int, len(classes))
	totals := make([]float64, len(classes))
	for i := range counts {
		counts[i] = map[uint32]int{}
		ports[i] = map[int]int{}
	}
	for _, e := range examples {
		c := index[e.Label]
		docs[c]++
		if e.Port > 0 {
			ports[c][e.Port]++
		}
		seen := map[uint32]bool{}
		for _, f := range Features(e.Banner) {
			if seen[f] {
				continue
			}
			seen[f] = true
			counts[c][f]++
			totals[c]++
		}
	}
	m := &Model{Classes: classes, Temperature: 1, PortWeight: 1}
	n := float64(len(examples))
	for c := range classes {
		// A flattened prior: the corpus over-represents some protocols (web
		// servers), which says nothing about what a given port will run.
		m.LogPrior = append(m.LogPrior, float32(0.3*math.Log(docs[c]/n)))
		denom := totals[c] + opt.Alpha*Buckets
		m.Default = append(m.Default, float32(math.Log(opt.Alpha/denom)))
		keys := make([]uint32, 0, len(counts[c]))
		for f, k := range counts[c] {
			if k >= opt.MinCount {
				keys = append(keys, f)
			}
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		vals := make([]float32, len(keys))
		for i, f := range keys {
			vals[i] = float32(math.Log((float64(counts[c][f]) + opt.Alpha) / denom))
		}
		m.Keys = append(m.Keys, keys)
		m.Values = append(m.Values, vals)

		const beta = 1.0 // smoothing over the 65,535 possible ports
		pdenom := docs[c] + beta*65535
		pk := make([]int32, 0, len(ports[c]))
		for p := range ports[c] {
			pk = append(pk, int32(p))
		}
		sort.Slice(pk, func(i, j int) bool { return pk[i] < pk[j] })
		pv := make([]float32, len(pk))
		for i, p := range pk {
			pv[i] = float32(math.Log((float64(ports[c][int(p)]) + beta) / pdenom))
		}
		m.PortKeys = append(m.PortKeys, pk)
		m.PortValues = append(m.PortValues, pv)
		m.PortDefault = append(m.PortDefault, float32(math.Log(beta/pdenom)))
	}
	return m
}

// Calibrate picks, on held-out examples, how much the port counts against
// the banner and the temperature that minimizes the log-loss, so that a
// reported "90%" is right about nine times in ten.
func (m *Model) Calibrate(heldOut []Example) {
	bestW, bestT, bestLoss := float32(1), float32(1), math.Inf(1)
	for _, w := range []float32{0, 1, 2, 4, 8, 12, 16, 24, 32, 48, 64} {
		for _, t := range []float32{1, 2, 3, 4, 6, 8, 10, 12, 15, 20, 25, 30, 40, 50, 70, 100} {
			m.PortWeight, m.Temperature = w, t
			if loss := m.logLoss(heldOut); loss < bestLoss {
				bestW, bestT, bestLoss = w, t, loss
			}
		}
	}
	m.PortWeight, m.Temperature = bestW, bestT
}

func (m *Model) logLoss(examples []Example) float64 {
	var loss float64
	for _, e := range examples {
		p := 1e-9
		for _, g := range m.Classify(e.Banner, e.Port) {
			if g.ID == e.Label {
				p = math.Max(g.P, 1e-9)
				break
			}
		}
		loss -= math.Log(p)
	}
	return loss
}

// Size reports how many weights the model stores.
func (m *Model) Size() int {
	n := 0
	for _, k := range m.Keys {
		n += len(k)
	}
	return n
}
