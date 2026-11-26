package model

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/gob"
	"fmt"
	"math"
	"math/rand"
	"sort"
)

// Model is a trained classifier with two parts that each weigh one kind of
// evidence. Classes are dictionary IDs ("openssh", "redis") plus "other"
// for banners of services the dictionary lacks.
//
// The banner part is a multinomial logistic regression over the hashed
// features of Features. Its weights are stored by feature, quantized to one
// byte: the weights of feature Feats[i] are Weight[Start[i]:Start[i+1]]
// times Scale, for the classes Class[Start[i]:Start[i+1]]. A feature the
// model never kept weighs nothing for every class.
//
// The port part is log P(port | class), counted on the training data, which
// puts every service on unusual ports too: PortKeys/PortValues for the
// ports each class was seen on, PortDefault for any other. PortWeight
// scales it against the banner's scores, fitted on held-out data: how much a
// port number says once the banner has spoken.
type Model struct {
	Classes     []string
	Bias        []float32
	Feats       []uint32
	Start       []uint32
	Class       []uint8
	Weight      []byte // int8, two's complement
	Scale       float32
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
	b := m.bannerScores(Features(banner))
	return m.softmax(m.combine(b, m.portScores(port), m.PortWeight), m.Temperature)
}

func (m *Model) combine(banner, port []float64, w float32) []float64 {
	out := make([]float64, len(banner))
	for c := range out {
		out[c] = banner[c] + float64(w)*port[c]
	}
	return out
}

// portScores is log P(port | class), or nothing without a port.
func (m *Model) portScores(port int) []float64 {
	out := make([]float64, len(m.Classes))
	if port <= 0 {
		return out
	}
	for c := range out {
		pk := m.PortKeys[c]
		i := sort.Search(len(pk), func(i int) bool { return pk[i] >= int32(port) })
		if i < len(pk) && pk[i] == int32(port) {
			out[c] = float64(m.PortValues[c][i])
		} else {
			out[c] = float64(m.PortDefault[c])
		}
	}
	return out
}

func (m *Model) bannerScores(feats []uint32) []float64 {
	scores := make([]float64, len(m.Classes))
	for c := range scores {
		scores[c] = float64(m.Bias[c])
	}
	lo := 0
	for _, f := range feats { // both sorted: each search starts where the last ended
		i := lo + sort.Search(len(m.Feats)-lo, func(i int) bool { return m.Feats[lo+i] >= f })
		lo = i
		if i == len(m.Feats) || m.Feats[i] != f {
			continue
		}
		for j := m.Start[i]; j < m.Start[i+1]; j++ {
			scores[m.Class[j]] += float64(int8(m.Weight[j])) * float64(m.Scale)
		}
	}
	return scores
}

func (m *Model) softmax(scores []float64, temperature float32) []Guess {
	best := math.Inf(-1)
	for c := range scores {
		scores[c] /= float64(temperature)
		best = math.Max(best, scores[c])
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].P != out[j].P {
			return out[i].P > out[j].P
		}
		return out[i].ID < out[j].ID
	})
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
	if len(m.Classes) == 0 || len(m.Classes) > 256 || len(m.Bias) != len(m.Classes) || m.Temperature <= 0 ||
		len(m.Start) != len(m.Feats)+1 || len(m.Class) != len(m.Weight) || int(m.Start[len(m.Feats)]) != len(m.Weight) ||
		len(m.PortKeys) != len(m.Classes) || len(m.PortValues) != len(m.Classes) || len(m.PortDefault) != len(m.Classes) {
		return nil, fmt.Errorf("model: inconsistent weights")
	}
	for i := range m.Feats {
		if m.Start[i] > m.Start[i+1] || i > 0 && m.Feats[i-1] >= m.Feats[i] {
			return nil, fmt.Errorf("model: inconsistent weights")
		}
	}
	for _, c := range m.Class {
		if int(c) >= len(m.Classes) {
			return nil, fmt.Errorf("model: inconsistent weights")
		}
	}
	for c := range m.Classes {
		if len(m.PortKeys[c]) != len(m.PortValues[c]) {
			return nil, fmt.Errorf("model: inconsistent weights")
		}
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
	Epochs  int     // passes over the data at most
	Rate    float64 // FTRL-Proximal learning rate (alpha)
	L1      float64 // pushes useless weights to exactly zero: a smaller model
	L2      float64 // weight decay
	Balance float64 // 0 weighs every example alike, 1 weighs every class alike
	// Dropout hides this share of a banner's features, drawn anew at each
	// pass, so the model cannot lean on one memorized detail and learns to
	// use the port and the banner's structure as well.
	Dropout float64
	Seed    int64
	// Validate stops training once the log-loss on these examples stops
	// improving, and keeps the best pass.
	Validate []Example
	// Progress, if set, is called after each pass.
	Progress func(epoch int, trainLoss, validLoss float64)
}

// Train fits the banner part with FTRL-Proximal (per-weight adaptive steps,
// L1 and L2 regularization) on the softmax log-loss and counts
// the port part. PortWeight and Temperature are left at 1; call Calibrate
// with held-out data.
func Train(examples []Example, opt TrainOptions) *Model {
	if opt.Epochs <= 0 {
		opt.Epochs = 20
	}
	if opt.Rate <= 0 {
		opt.Rate = 0.2
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
	C := len(classes)

	type prepared struct {
		feats []uint32
		y     int
		w     float64
	}
	prep := func(set []Example) []prepared {
		var out []prepared
		for _, e := range set {
			y, ok := index[e.Label]
			if !ok {
				continue // a class the training data lacks cannot be learned
			}
			out = append(out, prepared{feats: Features(e.Banner), y: y, w: 1})
		}
		return out
	}
	train, valid := prep(examples), prep(opt.Validate)

	// Weigh classes so that the corpus' own imbalance (many web servers, few
	// POP3 servers) does not become a belief about what a port runs.
	counts := make([]float64, C)
	for _, e := range train {
		counts[e.y]++
	}
	var mean float64
	for i := range train {
		train[i].w = math.Pow(counts[train[i].y], -opt.Balance)
		mean += train[i].w
	}
	mean /= float64(len(train))
	for i := range train {
		train[i].w /= mean
	}

	W := make([]float32, Buckets*C)
	Z := make([]float32, Buckets*C) // FTRL state: the weight is a function of Z and N
	N := make([]float32, Buckets*C)
	B := make([]float64, C)
	GB := make([]float64, C)
	p := make([]float64, C)
	forward := func(W []float32, B []float64, feats []uint32) {
		best := math.Inf(-1)
		for c := 0; c < C; c++ {
			p[c] = B[c]
		}
		for _, f := range feats {
			row := W[int(f)*C : int(f)*C+C]
			for c, w := range row {
				p[c] += float64(w)
			}
		}
		for c := 0; c < C; c++ {
			best = math.Max(best, p[c])
		}
		var sum float64
		for c := 0; c < C; c++ {
			p[c] = math.Exp(p[c] - best)
			sum += p[c]
		}
		for c := 0; c < C; c++ {
			p[c] /= sum
		}
	}
	loss := func(W []float32, B []float64, set []prepared) float64 {
		var l float64
		for _, e := range set {
			forward(W, B, e.feats)
			l -= math.Log(math.Max(p[e.y], 1e-12))
		}
		return l / math.Max(float64(len(set)), 1)
	}

	r := rand.New(rand.NewSource(opt.Seed))
	order := r.Perm(len(train))
	bestW, bestB, bestLoss := []float32(nil), []float64(nil), math.Inf(1)
	worse := 0
	var dropped []uint32
	for epoch := 1; epoch <= opt.Epochs; epoch++ {
		r.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		var trainLoss float64
		for _, k := range order {
			e := train[k]
			feats := e.feats
			if opt.Dropout > 0 {
				dropped = dropped[:0]
				for _, f := range e.feats {
					if r.Float64() >= opt.Dropout {
						dropped = append(dropped, f)
					}
				}
				feats = dropped
			}
			forward(W, B, feats)
			trainLoss -= math.Log(math.Max(p[e.y], 1e-12))
			for c := 0; c < C; c++ {
				g := p[c]
				if c == e.y {
					g--
				}
				p[c] = g * e.w
				GB[c] += p[c] * p[c]
				B[c] -= opt.Rate * p[c] / math.Sqrt(GB[c]+1e-8)
			}
			for _, f := range feats {
				base := int(f) * C
				for c := 0; c < C; c++ {
					g := p[c]
					if math.Abs(g) < 1e-6 {
						continue
					}
					i := base + c
					n := float64(N[i])
					sigma := (math.Sqrt(n+g*g) - math.Sqrt(n)) / opt.Rate
					z := float64(Z[i]) + g - sigma*float64(W[i])
					n += g * g
					Z[i], N[i] = float32(z), float32(n)
					if math.Abs(z) <= opt.L1 {
						W[i] = 0
					} else {
						W[i] = float32(-(z - math.Copysign(opt.L1, z)) / ((1+math.Sqrt(n))/opt.Rate + opt.L2))
					}
				}
			}
		}
		trainLoss /= float64(len(train))
		vl := trainLoss
		if len(valid) > 0 {
			vl = loss(W, B, valid)
		}
		if opt.Progress != nil {
			opt.Progress(epoch, trainLoss, vl)
		}
		if vl < bestLoss-1e-4 {
			bestLoss, worse = vl, 0
			bestW = append(bestW[:0], W...)
			bestB = append(bestB[:0], B...)
		} else if worse++; worse >= 2 {
			break
		}
	}
	m := export(classes, bestW, bestB)
	countPorts(m, examples, index)
	return m
}

// countPorts fills the port part: log P(port | class), smoothed over the
// 65,535 possible ports.
func countPorts(m *Model, examples []Example, index map[string]int) {
	C := len(m.Classes)
	docs := make([]float64, C)
	ports := make([]map[int]int, C)
	for c := range ports {
		ports[c] = map[int]int{}
	}
	for _, e := range examples {
		c := index[e.Label]
		docs[c]++
		if e.Port > 0 {
			ports[c][e.Port]++
		}
	}
	const beta = 1.0
	for c := 0; c < C; c++ {
		denom := docs[c] + beta*65535
		pk := make([]int32, 0, len(ports[c]))
		for p := range ports[c] {
			pk = append(pk, int32(p))
		}
		sort.Slice(pk, func(i, j int) bool { return pk[i] < pk[j] })
		pv := make([]float32, len(pk))
		for i, p := range pk {
			pv[i] = float32(math.Log((float64(ports[c][int(p)]) + beta) / denom))
		}
		m.PortKeys = append(m.PortKeys, pk)
		m.PortValues = append(m.PortValues, pv)
		m.PortDefault = append(m.PortDefault, float32(math.Log(beta/denom)))
	}
	m.PortWeight = 1
}

// export keeps the weights L1 left non-zero and quantizes them to one byte.
func export(classes []string, W []float32, B []float64) *Model {
	C := len(classes)
	m := &Model{Classes: classes, Temperature: 1, PortWeight: 1, Start: []uint32{0}}
	for _, b := range B {
		m.Bias = append(m.Bias, float32(b))
	}
	var maxAbs float64
	for _, w := range W {
		maxAbs = math.Max(maxAbs, math.Abs(float64(w)))
	}
	m.Scale = float32(math.Max(maxAbs, 1e-6) / 127)
	for f := 0; f < Buckets; f++ {
		kept := false
		for c := 0; c < C; c++ {
			q := math.Round(float64(W[f*C+c]) / float64(m.Scale))
			if q == 0 {
				continue
			}
			m.Class = append(m.Class, uint8(c))
			m.Weight = append(m.Weight, byte(int8(q)))
			kept = true
		}
		if kept {
			m.Feats = append(m.Feats, uint32(f))
			m.Start = append(m.Start, uint32(len(m.Weight)))
		}
	}
	return m
}

// Calibrate picks, on held-out examples, how much the port counts against
// the banner and the temperature that minimize the log-loss, so that a
// reported "90%" is right about nine times in ten.
func (m *Model) Calibrate(heldOut []Example) {
	type pre struct {
		banner, port []float64
		label        string
	}
	var set []pre
	for _, e := range heldOut {
		set = append(set, pre{m.bannerScores(Features(e.Banner)), m.portScores(e.Port), e.Label})
	}
	bestW, bestT, bestLoss := float32(0), float32(1), math.Inf(1)
	for _, w := range []float32{0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1, 1.25, 1.5, 2, 2.5, 3, 4, 5, 6, 8} {
		for t := float32(0.5); t <= 16; t *= 1.05 {
			var loss float64
			for _, e := range set {
				p := 1e-9
				for _, g := range m.softmax(m.combine(e.banner, e.port, w), t) {
					if g.ID == e.label {
						p = math.Max(g.P, 1e-9)
						break
					}
				}
				loss -= math.Log(p)
			}
			if loss < bestLoss {
				bestW, bestT, bestLoss = w, t, loss
			}
		}
	}
	m.PortWeight, m.Temperature = bestW, bestT
}

// Size reports how many weights the model stores.
func (m *Model) Size() int { return len(m.Weight) }
