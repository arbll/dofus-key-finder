package decrypt

import (
	"errors"
	"fmt"

	"github.int.exe.xyz/arbll/dofus-key-finder/internal/maps"
)

// The key lengths observed in Dofus maps are 128 through 277 bytes.
const (
	MinKeyLength = 128
	MaxKeyLength = 277
)

var ErrNoKeyLength = errors.New("no plausible key length")

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

// PossibleKeyLengths returns every length for which each repeated key byte can
// decrypt all of its map positions to valid cell characters. The result is
// ordered from shortest to longest; multiples of a true period may also pass.
func PossibleKeyLengths(m maps.Map) ([]int, error) {
	data, err := m.EncryptedData()
	if err != nil {
		return nil, err
	}
	if len(data) < 2*MinKeyLength {
		return nil, fmt.Errorf("map %d (%s): need at least %d encrypted bytes to test a repeating key", m.ID, m.Date, 2*MinKeyLength)
	}

	var lengths []int
	for length := MinKeyLength; length <= MaxKeyLength && 2*length <= len(data); length++ {
		if keyLengthPossible(data, length) {
			lengths = append(lengths, length)
		}
	}
	if len(lengths) == 0 {
		return nil, fmt.Errorf("map %d (%s): %w", m.ID, m.Date, ErrNoKeyLength)
	}
	return lengths, nil
}

// KeyLength returns the shortest plausible repeating key length.
func KeyLength(m maps.Map) (int, error) {
	lengths, err := PossibleKeyLengths(m)
	if err != nil {
		return 0, err
	}
	return lengths[0], nil
}

func keyLengthPossible(data []byte, length int) bool {
	for offset := 0; offset < length; offset++ {
		possible := keyBytes{lo: ^uint64(0), hi: ^uint64(0)}
		for i := offset; i < len(data); i += length {
			possible = possible.intersect(possibleKeys[i%cellSize][data[i]])
			if possible.empty() {
				return false
			}
		}
	}
	return true
}
