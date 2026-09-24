package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/arbll/dofus-key-finder/internal/decrypt"
	"github.com/arbll/dofus-key-finder/internal/keys"
	"github.com/arbll/dofus-key-finder/internal/maps"
)

func main() {
	mapsPath := flag.String("maps-file", "data/maps.csv", "path to the maps CSV file")
	keysPath := flag.String("keys-file", "data/keys.csv", "key inventory to read and update")
	flag.Parse()
	log.SetFlags(0)
	if err := run(*mapsPath, *keysPath, os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func run(mapsPath, keysPath string, output, diagnostics io.Writer) error {
	mapAbs, err := filepath.Abs(mapsPath)
	if err != nil {
		return err
	}
	keyAbs, err := filepath.Abs(keysPath)
	if err != nil {
		return err
	}
	if mapAbs == keyAbs {
		return fmt.Errorf("maps-file and keys-file must be different files")
	}
	loaded, err := maps.Load(mapsPath)
	if err != nil {
		return err
	}
	previous, err := keys.Load(keysPath)
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}
	// Validate identity before any recovery or writes. Different revisions of
	// the same map are independent, and must never share an inventory entry.
	seen := make(map[keys.Version]bool)
	for _, m := range loaded {
		version := keys.Version{ID: m.ID, Date: m.Date}
		if seen[version] {
			return fmt.Errorf("duplicate map %d (%s)", m.ID, m.Date)
		}
		seen[version] = true
	}
	entries, stats := process(loaded, previous, diagnostics)
	if err := keys.Save(keysPath, entries); err != nil {
		return fmt.Errorf("save keys: %w", err)
	}
	stats.print(output, keysPath, previous, entries)
	return nil
}

type results struct {
	total, plaintext, encrypted, invalid int
	recovered, ambiguous, failed         int
	beforeCoverage, afterCoverage        int
	added, confirmed, conflicts          int
}

func process(loaded []maps.Map, previous []keys.Entry, diagnostics io.Writer) ([]keys.Entry, results) {
	entries := slices.Clone(previous)
	index := make(map[keys.Version]int, len(entries))
	for i, entry := range entries {
		index[entry.Version] = i
	}
	stats := results{total: len(loaded)}
	for _, m := range loaded {
		// Encrypted mapData is hexadecimal; plaintext is ten-character cells.
		if _, err := hex.DecodeString(m.MapData); err != nil {
			if isPlaintext(m.MapData) {
				stats.plaintext++
			} else {
				stats.invalid++
				fmt.Fprintf(diagnostics, "Map %d (%s): invalid map data\n", m.ID, m.Date)
			}
			continue
		}
		if len(m.MapData) == 0 {
			stats.invalid++
			fmt.Fprintf(diagnostics, "Map %d (%s): empty map data\n", m.ID, m.Date)
			continue
		}
		stats.encrypted++
		version := keys.Version{ID: m.ID, Date: m.Date}
		i, exists := index[version]
		if exists {
			stats.beforeCoverage++
			stats.afterCoverage++
		}
		key, err := decrypt.Key(m)
		if errors.Is(err, decrypt.ErrAmbiguous) {
			stats.ambiguous++
			continue
		}
		if err != nil {
			stats.failed++
			fmt.Fprintln(diagnostics, err)
			continue
		}
		stats.recovered++
		if exists {
			old, _ := keys.Decode(entries[i].Key) // Validated by keys.Load.
			if !bytes.Equal(old, key) {
				stats.conflicts++
				fmt.Fprintf(diagnostics, "Map %d (%s): recovered key conflicts with existing key; existing entry preserved\n", m.ID, m.Date)
				continue
			}
			stats.confirmed++
			entries[i].Status = "exact"
			// Preserve imported and the original encoded key, even when the
			// same bytes have a different URL-escaped representation.
			continue
		}
		index[version] = len(entries)
		entries = append(entries, keys.Entry{Version: version, Key: keys.Encode(key), Imported: false, Status: "exact"})
		stats.added++
		stats.afterCoverage++
	}
	return entries, stats
}

func isPlaintext(data string) bool {
	return len(data) > 0 && len(data)%10 == 0 && strings.IndexFunc(data, func(r rune) bool {
		return !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_", r)
	}) == -1
}

func percent(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(n) / float64(total)
}

func (s results) print(w io.Writer, path string, previous, entries []keys.Entry) {
	fmt.Fprintf(w, "Maps: %d map versions (%d plaintext, %d encrypted, %d invalid)\n", s.total, s.plaintext, s.encrypted, s.invalid)
	fmt.Fprintf(w, "Encrypted maps with keys: %d/%d (%.2f%%)\n", s.afterCoverage, s.encrypted, percent(s.afterCoverage, s.encrypted))
	fmt.Fprintf(w, "Plaintext or key available: %d/%d (%.2f%%)\n", s.plaintext+s.afterCoverage, s.total, percent(s.plaintext+s.afterCoverage, s.total))
	fmt.Fprintf(w, "Exact recovery this run: %d/%d (%.2f%%); ambiguous: %d; failed: %d\n", s.recovered, s.encrypted, percent(s.recovered, s.encrypted), s.ambiguous, s.failed)
	fmt.Fprintf(w, "Existing keys confirmed: %d; conflicts preserved: %d\n", s.confirmed, s.conflicts)

	statuses := make(map[string]int)
	imported, changed, unchanged := 0, 0, 0
	for i, entry := range entries {
		statuses[entry.Status]++
		if entry.Imported {
			imported++
		}
		if i < len(previous) {
			if entry == previous[i] {
				unchanged++
			} else {
				changed++
			}
		}
	}
	fmt.Fprintf(w, "Key inventory: %d total (%d imported, %d generated)\n", len(entries), imported, len(entries)-imported)
	var names []string
	for status := range statuses {
		names = append(names, status)
	}
	slices.Sort(names)
	for _, name := range names {
		fmt.Fprintf(w, "  Status %s: %d\n", name, statuses[name])
	}
	fmt.Fprintln(w, "Coverage includes existing keys with unverified status; exact means unique under the current constraints.")
	fmt.Fprintf(w, "\nChanges to %s:\n", path)
	fmt.Fprintf(w, "  Keys: %d -> %d (+%d added, 0 replaced, 0 removed)\n", len(previous), len(entries), s.added)
	fmt.Fprintf(w, "  Status updated to exact: %d; existing entries unchanged: %d\n", changed, unchanged)
	fmt.Fprintf(w, "  Encrypted-map coverage: %.2f%% -> %.2f%% (+%.2f percentage points)\n", percent(s.beforeCoverage, s.encrypted), percent(s.afterCoverage, s.encrypted), percent(s.added, s.encrypted))
}
