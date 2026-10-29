package decrypt

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/arbll/dofus-key-finder/internal/maps"
)

// filterKeys returns allowed bytes at each position of the repeating XOR key,
// aligned with the ciphertext. Their Cartesian product is the set of complete
// candidate keys. Keeping it factored avoids allocating exponentially many keys.
// A nil result means no key can satisfy every cell character constraint.
func filterKeys(m maps.Map, length int) (keyCandidates [][]byte, err error) {
	data, err := m.EncryptedData()
	if err != nil {
		return nil, err
	}
	if length <= 0 || length > len(data) {
		return nil, fmt.Errorf("map %d (%s): invalid key length %d for %d encrypted bytes", m.ID, m.Date, length, len(data))
	}

	keyCandidates = make([][]byte, length)
	for offset := range length {
		possible := keyByteCandidates(data, length, offset)
		if possible.empty() {
			return nil, nil
		}
		for possible.lo != 0 {
			keyCandidates[offset] = append(keyCandidates[offset], byte(bits.TrailingZeros64(possible.lo)))
			possible.lo &= possible.lo - 1
		}
		for possible.hi != 0 {
			keyCandidates[offset] = append(keyCandidates[offset], byte(64+bits.TrailingZeros64(possible.hi)))
			possible.hi &= possible.hi - 1
		}
	}
	return keyCandidates, nil
}

func keyByteCandidates(data []byte, length, offset int) keyBytes {
	possible := keyBytes{lo: ^uint64(0), hi: ^uint64(0)}
	for i := offset; i < len(data); i += length {
		possible = possible.intersect(possibleKeys[i%cellSize][data[i]])
		if possible.empty() {
			break
		}
	}
	return possible
}

func candidateCount(keyCandidates [][]byte) *big.Int {
	count := new(big.Int)
	if len(keyCandidates) == 0 {
		return count
	}
	count.SetInt64(1)
	var factor big.Int
	for _, candidates := range keyCandidates {
		count.Mul(count, factor.SetInt64(int64(len(candidates))))
	}
	return count
}
