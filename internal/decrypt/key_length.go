package decrypt

import (
	"errors"
	"fmt"

	"github.com/arbll/dofus-key-finder/internal/maps"
)

// The key lengths observed in Dofus maps are 128 through 277 bytes.
const (
	minKeyLength = 128
	maxKeyLength = 277
)

var errNoKeyLength = errors.New("no plausible key length")

// keyBytes is a bit set of possible ASCII key bytes (32 through 127).
type keyBytes struct {
	lo uint64 // bytes 0 through 63
	hi uint64 // bytes 64 through 127
}

func (s keyBytes) intersect(other keyBytes) keyBytes {
	return keyBytes{s.lo & other.lo, s.hi & other.hi}
}

func (s keyBytes) empty() bool {
	return s.lo == 0 && s.hi == 0
}

func (s *keyBytes) add(value byte) {
	if value < 64 {
		s.lo |= uint64(1) << value
	} else {
		s.hi |= uint64(1) << (value - 64)
	}
}

var possibleKeys = buildPossibleKeys()

func buildPossibleKeys() [cellSize][256]keyBytes {
	var table [cellSize][256]keyBytes
	for position, characters := range cellCharacters {
		for encrypted := range 256 {
			for i := 0; i < len(characters); i++ {
				key := byte(encrypted) ^ characters[i]
				if key >= 32 && key <= 127 {
					table[position][encrypted].add(key)
				}
			}
		}
	}
	return table
}

// possibleKeyLengths returns every length for which each repeated key byte can
// decrypt all of its map positions to valid cell characters. The result is
// ordered from shortest to longest; multiples of a true period may also pass.
func possibleKeyLengths(m maps.Map) ([]int, error) {
	data, err := m.EncryptedData()
	if err != nil {
		return nil, err
	}
	if len(data) < 2*minKeyLength {
		return nil, fmt.Errorf("map %d (%s): need at least %d encrypted bytes to test a repeating key", m.ID, m.Date, 2*minKeyLength)
	}

	var lengths []int
	for length := minKeyLength; length <= maxKeyLength && 2*length <= len(data); length++ {
		if keyLengthPossible(data, length) {
			lengths = append(lengths, length)
		}
	}
	if len(lengths) == 0 {
		return nil, fmt.Errorf("map %d (%s): %w", m.ID, m.Date, errNoKeyLength)
	}
	return lengths, nil
}

// keyLength returns the shortest plausible repeating key length.
func keyLength(m maps.Map) (int, error) {
	lengths, err := possibleKeyLengths(m)
	if err != nil {
		return 0, err
	}
	return lengths[0], nil
}

func keyLengthPossible(data []byte, length int) bool {
	for offset := 0; offset < length; offset++ {
		if keyByteCandidates(data, length, offset).empty() {
			return false
		}
	}
	return true
}
