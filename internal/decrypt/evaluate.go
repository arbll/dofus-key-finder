package decrypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/arbll/dofus-key-finder/internal/keys"
	"github.com/arbll/dofus-key-finder/internal/maps"
	"io"
	"slices"
)

type sample struct {
	m                maps.Map
	key, plain, data []byte
	candidates       [][]byte
	split            int
	ambiguous        bool
	imported         bool
}

// splitSamples keeps all versions of an ID and identical plaintexts together,
// including transitive connections. No held-out plaintext trains a model.
func splitSamples(samples []sample) {
	parent := make([]int, len(samples))
	for i := range parent {
		parent[i] = i
	}
	var root func(int) int
	root = func(i int) int {
		if parent[i] != i {
			parent[i] = root(parent[i])
		}
		return parent[i]
	}
	join := func(a, b int) {
		a, b = root(a), root(b)
		if a > b {
			a, b = b, a
		}
		parent[b] = a
	}
	ids := map[int]int{}
	hashes := map[[32]byte]int{}
	for i, s := range samples {
		if j, ok := ids[s.m.ID]; ok {
			join(i, j)
		} else {
			ids[s.m.ID] = i
		}
		h := sha256.Sum256(s.plain)
		if j, ok := hashes[h]; ok {
			join(i, j)
		} else {
			hashes[h] = i
		}
	}
	for i := range samples {
		h := sha256.Sum256([]byte(fmt.Sprintf("dofus-predict-v1:%d", samples[root(i)].m.ID)))
		bucket := binary.LittleEndian.Uint64(h[:8]) % 10
		samples[i].split = 0
		if bucket >= 6 {
			samples[i].split = 1
		}
		if bucket >= 8 {
			samples[i].split = 2
		}
	}
}

type metric struct{ n, full, ambiguous, solved, byteN, byteOK, importedN, importedOK, exactOnlyN, exactOnlyOK int }

func evaluate(model *Model, samples []sample, split int) metric {
	var r metric
	for _, s := range samples {
		if s.split != split {
			continue
		}
		r.n++
		result, err := Key(s.m, model)
		got := result.Key
		correct := err == nil && bytes.Equal(got, s.key)
		if correct {
			r.full++
		}
		if !s.ambiguous {
			continue
		}
		r.ambiguous++
		if correct {
			r.solved++
		}
		if s.imported {
			r.importedN++
			if correct {
				r.importedOK++
			}
		} else {
			r.exactOnlyN++
			if correct {
				r.exactOnlyOK++
			}
		}
		// Aligned bytes isolate prediction quality from checksum-induced rotation.
		aligned, want := rotate(got), rotate(s.key)
		for i, c := range s.candidates {
			if len(c) > 1 {
				r.byteN++
				if i < len(aligned) && i < len(want) && aligned[i] == want[i] {
					r.byteOK++
				}
			}
		}
	}
	return r
}
func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}
func row(w io.Writer, split, name string, r metric) {
	fmt.Fprintf(w, "| %s | %s | %d/%d (%.2f%%) | %d/%d (%.2f%%) | %d/%d (%.2f%%) |\n", split, name, r.full, r.n, pct(r.full, r.n), r.solved, r.ambiguous, pct(r.solved, r.ambiguous), r.byteOK, r.byteN, pct(r.byteOK, r.byteN))
}

// Evaluate reports grouped held-out accuracy without modifying inventories.
func Evaluate(loaded []maps.Map, imported, exact []keys.Entry, w io.Writer) error {
	known := map[keys.Version][]byte{}
	sources := map[keys.Version]bool{}
	for group, entries := range [][]keys.Entry{imported, exact} {
		for _, e := range entries {
			k, err := keys.Decode(e.Key)
			if err != nil {
				return err
			}
			if old, ok := known[e.Version]; ok && !bytes.Equal(old, k) {
				return fmt.Errorf("conflicting known keys for %v", e.Version)
			}
			known[e.Version] = k
			if group == 0 {
				sources[e.Version] = true
			}
		}
	}
	seen := map[keys.Version]bool{}
	var samples []sample
	unsupported := 0
	for _, m := range loaded {
		v := keys.Version{ID: m.ID, Date: m.Date}
		if seen[v] {
			return fmt.Errorf("duplicate map %v", v)
		}
		seen[v] = true
		k, ok := known[v]
		if !ok {
			continue
		}
		data, err := m.EncryptedData()
		if err != nil {
			return err
		}
		aligned := rotate(k)
		p := make([]byte, len(data))
		for i, b := range data {
			p[i] = b ^ aligned[i%len(aligned)]
		}
		c, err := candidates(m)
		ambiguous := err != nil || len(c) == 0
		supported := err == nil && len(c) == len(aligned)
		for i, choices := range c {
			if len(choices) > 1 {
				ambiguous = true
			}
			if i >= len(aligned) || !slices.Contains(choices, aligned[i]) {
				supported = false
			}
		}
		if !supported {
			unsupported++
			ambiguous = true
		}
		samples = append(samples, sample{m: m, key: k, plain: p, data: data, candidates: c, ambiguous: ambiguous, imported: sources[v]})
	}
	missing := len(known) - len(samples)
	if missing > 0 {
		return fmt.Errorf("%d known keys have no map", missing)
	}
	if unsupported > 0 {
		return fmt.Errorf("%d known keys incompatible with solver; refusing to train on unvalidated plaintext", unsupported)
	}
	slices.SortFunc(samples, func(a, b sample) int {
		if a.m.ID != b.m.ID {
			return a.m.ID - b.m.ID
		}
		if a.m.Date < b.m.Date {
			return -1
		}
		if a.m.Date > b.m.Date {
			return 1
		}
		return 0
	})
	splitSamples(samples)

	var counts, amb [3]int
	for _, s := range samples {
		counts[s.split]++
		if s.ambiguous {
			amb[s.split]++
		}

	}
	if counts[0] == 0 || amb[1] == 0 || amb[2] == 0 {
		return fmt.Errorf("insufficient train/validation/test samples: %v; ambiguous %v", counts, amb)
	}
	fmt.Fprintf(w, "# Predictive key evaluation\n\nKnown versions: %d (union of %d imported and %d exact entries).\n\n", len(samples), len(imported), len(exact))
	fmt.Fprintf(w, "Fixed SHA-256 grouped split (target 60/20/20): train %d, validation %d, test %d; ambiguous %d/%d/%d. All versions of a map ID and identical decrypted plaintexts share a partition. No predictions or held-out plaintexts enter training. Solver constraints are pre-existing and fixed.\n\n", counts[0], counts[1], counts[2], amb[0], amb[1], amb[2])
	fmt.Fprintln(w, "Position model: separate smoothed frequencies for the ten cell positions, summed as log likelihoods over repeated key-byte observations.")
	var plaintexts [][]byte
	for _, s := range samples {
		if s.split == 0 {
			plaintexts = append(plaintexts, s.plain)
		}
	}
	model := train(plaintexts)
	fmt.Fprintln(w, "\n| Split | Model | Whole key, all | Whole key, ambiguous only | Unresolved aligned bytes |\n| --- | --- | --- | --- | --- |")
	row(w, "validation", "position", evaluate(model, samples, 1))
	row(w, "test", "position", evaluate(model, samples, 2))
	fmt.Fprintln(w, "\nPredictions are statistical guesses. Known keys may not represent unknown maps; this test partition was inspected during earlier experiments.")
	return nil
}
