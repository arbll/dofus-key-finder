// Package decrypt recovers repeating XOR keys used for encrypted Dofus maps.
package decrypt

import (
	"fmt"

	"github.com/arbll/dofus-key-finder/internal/maps"
)

// Key returns the recovered, unescaped key bytes in their original order.
// It uses the shortest plausible repeating key length and requires exactly one
// candidate; ambiguity errors include the exact number of candidate keys.
func Key(m maps.Map) ([]byte, error) {
	length, err := keyLength(m)
	if err != nil {
		return nil, err
	}
	keyCandidates, err := filterKeys(m, length)
	if err != nil {
		return nil, err
	}
	count := candidateCount(keyCandidates)
	if !count.IsInt64() || count.Int64() != 1 {
		return nil, fmt.Errorf("map %d (%s): %s candidate keys remain for key length %d; need exactly 1", m.ID, m.Date, count, length)
	}

	// Encryption starts at twice the key checksum (sum of bytes modulo 16).
	// Rotation preserves that checksum, so undo it after recovering the XOR key.
	// Reference: https://github.com/hussein-aitlahcen/dofus-map-key/blob/master/Program.cs
	checksum := 0
	for _, candidates := range keyCandidates {
		checksum += int(candidates[0])
	}
	shift := 2 * (checksum % 16)
	key := make([]byte, length)
	for i, candidates := range keyCandidates {
		key[(i+shift)%length] = candidates[0]
	}
	return key, nil
}

// Each map cell has ten bytes. These are the observed plaintext characters at
// each byte position. The sets combine plaintext maps in data/maps.csv with the
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
