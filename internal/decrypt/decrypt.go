// Package decrypt recovers repeating XOR keys used for encrypted Dofus maps.
package decrypt

import (
	"errors"
	"fmt"

	"github.com/arbll/dofus-key-finder/internal/maps"
)

// ErrAmbiguous means the current constraints allow more than one key.
var ErrAmbiguous = errors.New("ambiguous key")

// Result contains the unescaped key in its original order and recovery details.
// Stats remain available when Key returns ErrAmbiguous without a trained model.
type Result struct {
	Key            []byte
	UsedPrediction bool
	Stats          Stats
}

// Stats describes deterministic constraints, not calibrated confidence.
type Stats struct {
	KeyLength       int
	EncryptedBytes  int
	DeterminedBytes int
	AmbiguousBytes  int
	CandidateCount  string // Exact count; may exceed machine integer limits.
}

// Key first applies deterministic constraints. A trained model resolves remaining
// ambiguous bytes; nil (or an empty model) requests deterministic recovery only.
func Key(m maps.Map, model *Model) (Result, error) {
	var result Result
	candidates, err := Candidates(m)
	if err != nil {
		return result, err
	}
	data, err := m.EncryptedData()
	if err != nil {
		return result, err
	}
	count := candidateCount(candidates)
	result.Stats = Stats{KeyLength: len(candidates), EncryptedBytes: len(data), CandidateCount: count.String()}
	for _, c := range candidates {
		if len(c) == 1 {
			result.Stats.DeterminedBytes++
		} else {
			result.Stats.AmbiguousBytes++
		}
	}
	if count.Sign() == 0 {
		return result, fmt.Errorf("map %d (%s): no candidate keys", m.ID, m.Date)
	}
	if result.Stats.AmbiguousBytes == 0 {
		aligned := make([]byte, len(candidates))
		for i, c := range candidates {
			aligned[i] = c[0]
		}
		result.Key = Unrotate(aligned)
		return result, nil
	}
	if model == nil || model.totals[0] == 0 {
		return result, fmt.Errorf("map %d (%s): %s candidate keys remain for key length %d: %w", m.ID, m.Date, count, len(candidates), ErrAmbiguous)
	}
	result.Key, err = model.Guess(data, candidates)
	result.UsedPrediction = err == nil
	return result, err
}

// Each map cell has ten bytes. These are the observed plaintext characters at
// each byte position. The sets combine plaintext maps in data/maps.csv.gz with the
// published position statistics at https://arthur.bell.al/etc/cell_stats.json.
const cellSize = 10

const cellAlphabet = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

var cellCharacters = [cellSize]string{
	"GHOPab",
	"0123457AIKLNOPRZabcdefghijklmnoprstuwxyz",
	"2345678ACFGHIJKLMNOPQRSVWXYZ_abcdefghijklmnopqrstuvwxyz",
	cellAlphabet,
	"048CGKOQSWefghimqsu",
	"-012345678ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz",
	cellAlphabet,
	"0134GHJKLNOSWXYZabcdefghijklmnpqrtuvwxy",
	cellAlphabet,
	cellAlphabet,
}
