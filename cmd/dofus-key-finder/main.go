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

type inventory struct {
	imported, exact, predicted []keys.Entry
}

type inventoryPaths struct {
	imported, exact, predicted string
}

func main() {
	mapsPath := flag.String("maps-file", "data/maps.csv", "path to the maps CSV file")
	imported := flag.String("imported-keys-file", "data/keys-imported.csv", "imported keys to read")
	exact := flag.String("exact-keys-file", "data/keys-exact.csv", "exact keys to read and update")
	predicted := flag.String("predicted-keys-file", "data/keys-predicted.csv", "predicted keys to read and promote when recovered exactly")
	flag.Parse()
	log.SetFlags(0)
	if err := run(*mapsPath, inventoryPaths{*imported, *exact, *predicted}, os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func run(mapsPath string, paths inventoryPaths, output, diagnostics io.Writer) error {
	seenPaths := make(map[string]bool)
	for _, path := range []string{mapsPath, paths.imported, paths.exact, paths.predicted} {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if seenPaths[abs] {
			return fmt.Errorf("maps and key inventories must be different files: %s", path)
		}
		seenPaths[abs] = true
	}
	loaded, err := maps.Load(mapsPath)
	if err != nil {
		return err
	}
	var previous inventory
	seenKeys := make(map[keys.Version]string)
	for _, input := range []struct {
		path    string
		entries *[]keys.Entry
	}{
		{paths.imported, &previous.imported}, {paths.exact, &previous.exact}, {paths.predicted, &previous.predicted},
	} {
		entries, err := keys.Load(input.path)
		if err != nil {
			return fmt.Errorf("load %s: %w", input.path, err)
		}
		for _, entry := range entries {
			if other, exists := seenKeys[entry.Version]; exists && input.path == paths.predicted {
				return fmt.Errorf("duplicate map %d (%s) in %s and %s", entry.ID, entry.Date, other, input.path)
			}
			seenKeys[entry.Version] = input.path
		}
		*input.entries = entries
	}
	seen := make(map[keys.Version]bool)
	for _, m := range loaded {
		version := keys.Version{ID: m.ID, Date: m.Date}
		if seen[version] {
			return fmt.Errorf("duplicate map %d (%s)", m.ID, m.Date)
		}
		seen[version] = true
	}
	entries, stats := process(loaded, previous, diagnostics)
	if err := keys.Save(paths.exact, entries.exact); err != nil {
		return fmt.Errorf("save exact keys: %w", err)
	}
	if err := keys.Save(paths.predicted, entries.predicted); err != nil {
		return fmt.Errorf("save predicted keys: %w", err)
	}
	stats.print(output, entries)
	return nil
}

type results struct {
	total, plaintext, encrypted, invalid int
	recovered, ambiguous, failed         int
	beforeCoverage, afterCoverage        int
	added, confirmed, conflicts          int
	promoted, corrected                  int
}

func process(loaded []maps.Map, previous inventory, diagnostics io.Writer) (inventory, results) {
	entries := inventory{imported: slices.Clone(previous.imported), exact: slices.Clone(previous.exact)}
	known := make(map[keys.Version]keys.Entry)
	exact := make(map[keys.Version]bool)
	for _, entry := range previous.exact {
		exact[entry.Version] = true
	}
	predicted := make(map[keys.Version]keys.Entry)
	for _, group := range [][]keys.Entry{previous.imported, previous.exact} {
		for _, entry := range group {
			known[entry.Version] = entry
		}
	}
	for _, entry := range previous.predicted {
		predicted[entry.Version] = entry
	}
	promoted := make(map[keys.Version]bool)
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
		existing, exists := known[version]
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
			old, _ := keys.Decode(existing.Key) // Validated by keys.Load.
			if !bytes.Equal(old, key) {
				stats.conflicts++
				fmt.Fprintf(diagnostics, "Map %d (%s): recovered key conflicts with existing key; existing entry preserved\n", m.ID, m.Date)
			} else {
				stats.confirmed++
			}
		}
		if exact[version] {
			continue
		}
		if prediction, ok := predicted[version]; ok {
			stats.promoted++
			promoted[version] = true
			old, _ := keys.Decode(prediction.Key)
			if !bytes.Equal(old, key) {
				stats.corrected++
				fmt.Fprintf(diagnostics, "Map %d (%s): prediction differs from exact recovery; moved recovered key to exact inventory\n", m.ID, m.Date)
			}
		} else {
			stats.added++
		}
		entry := keys.Entry{Version: version, Key: keys.Encode(key)}
		known[version] = entry
		entries.exact = append(entries.exact, entry)
		exact[version] = true
		if !exists {
			stats.afterCoverage++
		}
	}
	for _, entry := range previous.predicted {
		if !promoted[entry.Version] {
			entries.predicted = append(entries.predicted, entry)
		}
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

func (s results) print(w io.Writer, entries inventory) {
	fmt.Fprintf(w, "Maps: %d map versions (%d plaintext, %d encrypted, %d invalid)\n", s.total, s.plaintext, s.encrypted, s.invalid)
	fmt.Fprintf(w, "Encrypted maps with imported or exact keys: %d/%d (%.2f%%)\n", s.afterCoverage, s.encrypted, percent(s.afterCoverage, s.encrypted))
	fmt.Fprintf(w, "Plaintext or imported/exact key available: %d/%d (%.2f%%)\n", s.plaintext+s.afterCoverage, s.total, percent(s.plaintext+s.afterCoverage, s.total))
	fmt.Fprintf(w, "Exact recovery this run: %d/%d (%.2f%%); ambiguous: %d; failed: %d\n", s.recovered, s.encrypted, percent(s.recovered, s.encrypted), s.ambiguous, s.failed)
	fmt.Fprintf(w, "Existing keys confirmed: %d; conflicts preserved: %d\n", s.confirmed, s.conflicts)
	fmt.Fprintf(w, "Key inventories: %d imported, %d exact, %d predicted\n", len(entries.imported), len(entries.exact), len(entries.predicted))
	fmt.Fprintf(w, "Exact keys: +%d added; predictions promoted: %d (%d corrected)\n", s.added, s.promoted, s.corrected)
	fmt.Fprintln(w, "Coverage includes unverified imported keys and excludes predictions; exact means unique under the current constraints.")
	fmt.Fprintf(w, "Encrypted-map coverage: %.2f%% -> %.2f%%\n", percent(s.beforeCoverage, s.encrypted), percent(s.afterCoverage, s.encrypted))
}
