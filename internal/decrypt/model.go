package decrypt

import (
	"fmt"
	"github.com/arbll/dofus-key-finder/internal/maps"
	"math"
	"slices"
)

// Model learns smoothed plaintext frequencies at each of the ten cell positions.
type Model struct {
	counts [10][256]float64
	totals [10]float64
}

func train(plaintexts [][]byte) *Model {
	m := &Model{}
	for _, p := range plaintexts {
		m.add(p)
	}
	return m
}
func (m *Model) add(p []byte) {
	for i, b := range p {
		m.counts[i%10][b]++
		m.totals[i%10]++
	}
}

// guess maximizes independent byte log likelihood within candidate constraints.
// Singleton positions stay fixed. Ties choose the first (smallest) candidate.
func (m *Model) guess(data []byte, candidates [][]byte) ([]byte, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no candidates")
	}
	var logs [10][256]float64
	for p := range 10 {
		for b := range 256 {
			prob := (m.counts[p][b] + 1) / (m.totals[p] + 256)
			logs[p][b] = math.Log(prob)
		}
	}
	aligned := make([]byte, len(candidates))
	for offset, choices := range candidates {
		if len(choices) == 0 {
			return nil, fmt.Errorf("empty candidate position %d", offset)
		}
		best := math.Inf(-1)
		for _, k := range choices {
			score := 0.0
			for i := offset; i < len(data); i += len(candidates) {
				score += logs[i%10][data[i]^k]
			}
			if score > best {
				best = score
				aligned[offset] = k
			}
		}
	}
	return unrotate(aligned), nil
}

// Observe adds plaintext from a known key only when the key satisfies the
// deterministic solver. Callers must not use predictions as training labels.
func (m *Model) Observe(source maps.Map, key []byte) error {
	candidates, err := candidates(source)
	if err != nil {
		return err
	}
	aligned := rotate(key)
	if len(aligned) != len(candidates) {
		return fmt.Errorf("known key length does not match solver")
	}
	for i, c := range candidates {
		if !slices.Contains(c, aligned[i]) {
			return fmt.Errorf("known key violates solver constraints at byte %d", i)
		}
	}
	data, err := source.EncryptedData()
	if err != nil {
		return err
	}
	for i, b := range data {
		data[i] = b ^ aligned[i%len(aligned)]
	}
	m.add(data)
	return nil
}
