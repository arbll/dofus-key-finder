package decrypt

import "github.com/arbll/dofus-key-finder/internal/maps"

// Candidates returns the deterministic solver's allowed bytes, aligned to the
// ciphertext, at its shortest plausible key length. It does not use known keys.
func Candidates(m maps.Map) ([][]byte, error) {
	length, err := keyLength(m)
	if err != nil {
		return nil, err
	}
	return filterKeys(m, length)
}

// Rotate aligns an original key with the ciphertext.
func Rotate(key []byte) []byte {
	shift := checksumShift(key)
	out := make([]byte, len(key))
	for i := range out {
		out[i] = key[(i+shift)%len(key)]
	}
	return out
}

// Unrotate restores the original ordering of a ciphertext-aligned key.
func Unrotate(key []byte) []byte {
	shift := checksumShift(key)
	out := make([]byte, len(key))
	for i, b := range key {
		out[(i+shift)%len(key)] = b
	}
	return out
}

func checksumShift(key []byte) int {
	sum := 0
	for _, b := range key {
		sum += int(b)
	}
	return 2 * (sum % 16)
}
