package decrypt

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/arbll/dofus-key-finder/internal/maps"
)

func TestFilterKeys(t *testing.T) {
	// A short period revisits different cell positions, including a partial cell.
	plaintext := []byte("bhaaeaaaaabhaaeaaaaabhaaeaaaaabha")
	key := []byte("A%+")
	data := make([]byte, len(plaintext))
	for i, value := range plaintext {
		data[i] = value ^ key[i%len(key)]
	}
	m := maps.Map{MapData: hex.EncodeToString(data)}
	got, err := filterKeys(m, len(key))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(key) {
		t.Fatalf("got %d candidate positions, want %d", len(got), len(key))
	}
	// Check against exhaustive XOR validation, independently of the lookup table.
	for offset, candidates := range got {
		var want []byte
		for value := 32; value <= 127; value++ {
			valid := true
			for i := offset; i < len(data); i += len(key) {
				if !strings.ContainsRune(cellCharacters[i%cellSize], rune(data[i]^byte(value))) {
					valid = false
					break
				}
			}
			if valid {
				want = append(want, byte(value))
			}
		}
		if !bytes.Equal(candidates, want) {
			t.Errorf("offset %d: candidates %v, want %v", offset, candidates, want)
		}
		if !bytes.Contains(candidates, key[offset:offset+1]) {
			t.Errorf("offset %d: eliminated known key byte", offset)
		}
	}
}

func TestFilterKeysInvalidInput(t *testing.T) {
	for _, tt := range []struct {
		data   string
		length int
	}{
		{"not hex", 1}, {"00", 0}, {"00", -1}, {"00", 2}, {"", 1},
	} {
		if _, err := filterKeys(maps.Map{MapData: tt.data}, tt.length); err == nil {
			t.Errorf("filterKeys(%q, %d) accepted invalid input", tt.data, tt.length)
		}
	}
	candidates, err := filterKeys(maps.Map{MapData: "ff"}, 1)
	if err != nil || candidateCount(candidates).Sign() != 0 {
		t.Fatalf("impossible ciphertext: candidates = %v, error = %v", candidates, err)
	}
}

func TestCandidateCount(t *testing.T) {
	if candidateCount(nil).Sign() != 0 || candidateCount([][]byte{{1}, nil}).Sign() != 0 {
		t.Fatal("empty candidate sets must have zero complete keys")
	}
	candidates := make([][]byte, 128)
	for i := range candidates {
		candidates[i] = []byte{32, 33}
	}
	want := new(big.Int).Lsh(big.NewInt(1), 128)
	if got := candidateCount(candidates); got.Cmp(want) != 0 {
		t.Fatalf("count = %s, want %s", got, want)
	}
}

func TestKeyInvalidInput(t *testing.T) {
	for _, data := range []string{"not hex", "00", strings.Repeat("ff", 1000)} {
		key, err := Key(maps.Map{MapData: data})
		if err == nil || key != nil {
			t.Errorf("Key(%q): key = %v, error = %v", data[:min(len(data), 10)], key, err)
		}
	}
}

// TestKnownKeys evaluates every key, checks that filtering preserves it, and
// verifies that Key either returns that exact key or reports the full count.
// Run with go test ./internal/decrypt -run '^TestKnownKeys$' -v for percentiles.
func TestKnownKeys(t *testing.T) {
	file, err := os.Open("../../data/keys.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	rows, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 || !slices.Equal(rows[0], []string{"id", "date", "key"}) {
		t.Fatal("missing keys or unexpected keys CSV header")
	}
	type mapVersion struct {
		id   int
		date string
	}
	known := make(map[mapVersion][]byte, len(rows)-1)
	for _, row := range rows[1:] {
		id, err := strconv.Atoi(row[0])
		if err != nil {
			t.Fatal(err)
		}
		escaped, err := hex.DecodeString(row[2])
		if err != nil {
			t.Fatal(err)
		}
		key, err := url.QueryUnescape(string(escaped))
		if err != nil {
			t.Fatal(err)
		}
		version := mapVersion{id, row[1]}
		if _, exists := known[version]; exists {
			t.Fatalf("duplicate known map %v", version)
		}
		known[version] = []byte(key)
	}
	loaded, err := maps.Load("../../data/maps.csv")
	if err != nil {
		t.Fatal(err)
	}
	var counts []*big.Int
	recovered := 0
	for _, m := range loaded {
		version := mapVersion{m.ID, m.Date}
		want, ok := known[version]
		if !ok {
			continue
		}
		delete(known, version)
		length, err := keyLength(m)
		if err != nil {
			t.Errorf("map %v: %v", version, err)
			continue
		}
		if length != len(want) {
			t.Errorf("map %v: inferred length %d, known length %d", version, length, len(want))
		}
		candidates, err := filterKeys(m, length)
		if err != nil {
			t.Errorf("map %v: %v", version, err)
			continue
		}
		count := candidateCount(candidates)
		counts = append(counts, count)
		if count.Sign() == 0 {
			t.Errorf("map %v: eliminated all keys", version)
			continue
		}
		checksum := 0
		for _, value := range want {
			checksum += int(value) % 16
		}
		shift := (checksum % 16) * 2
		for offset, values := range candidates {
			if !slices.Contains(values, want[(offset+shift)%len(want)]) {
				t.Errorf("map %v: eliminated known key at offset %d", version, offset)
				break
			}
		}
		got, err := Key(m)
		if count.Cmp(big.NewInt(1)) == 0 {
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("map %v: recovered key differs from known key; error = %v", version, err)
			} else {
				recovered++
			}
		} else if got != nil || err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%s candidate keys", count)) {
			t.Errorf("map %v: expected error with %s candidates; key = %v, error = %v", version, count, got, err)
		}
	}
	if len(known) != 0 {
		t.Errorf("%d known keys have no matching map", len(known))
	}
	if len(counts) == 0 {
		t.Fatal("no maps evaluated")
	}
	slices.SortFunc(counts, func(a, b *big.Int) int { return a.Cmp(b) })
	t.Logf("evaluated=%d recovered=%d (%.2f%%) ambiguous=%d", len(counts), recovered, 100*float64(recovered)/float64(len(counts)), len(counts)-recovered)
	for _, percentile := range []int{100, 99, 95, 90, 75, 50} {
		// Nearest rank: ceil(p*N/100), with a zero-based slice index.
		count := counts[(percentile*len(counts)+99)/100-1]
		t.Logf("p%d=%s (%.6e)", percentile, count, new(big.Float).SetInt(count))
	}
}
