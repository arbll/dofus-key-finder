package main

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/arbll/dofus-key-finder/internal/decrypt"
	"github.com/arbll/dofus-key-finder/internal/keys"
	"github.com/arbll/dofus-key-finder/internal/maps"
)

// Exercise the actual solver using real map data, independent of keys.csv.
func recoveryFixtures(t *testing.T) (maps.Map, []byte, maps.Map) {
	t.Helper()
	loaded, err := maps.Load("../../data/maps.csv")
	if err != nil {
		t.Fatal(err)
	}
	var solved, ambiguous maps.Map
	var recovered []byte
	for _, m := range loaded {
		if _, err := m.EncryptedData(); err != nil {
			continue
		}
		key, err := decrypt.Key(m)
		if err == nil && recovered == nil {
			solved, recovered = m, key
		} else if errors.Is(err, decrypt.ErrAmbiguous) {
			ambiguous = m
		}
		if recovered != nil && ambiguous.MapData != "" {
			return solved, recovered, ambiguous
		}
	}
	t.Fatal("missing recovery fixtures")
	return maps.Map{}, nil, maps.Map{}
}

func TestProcessPreservesProvenanceAndConflicts(t *testing.T) {
	solved, key, ambiguous := recoveryFixtures(t)
	// Distinct versions of the same map must stay independent.
	var loaded []maps.Map
	for _, date := range []string{"new", "imported", "generated", "conflict"} {
		m := solved
		m.Date = date
		loaded = append(loaded, m)
	}
	ambiguous.Date = "ambiguous"
	loaded = append(loaded, ambiguous,
		maps.Map{ID: -1, Date: "plain", MapData: "bhaaeaaaaa"},
		maps.Map{ID: -1, Date: "invalid", MapData: "!"},
		maps.Map{ID: -1, Date: "empty"},
		maps.Map{ID: -1, Date: "impossible", MapData: strings.Repeat("ff", 300)})
	encoded := hex.EncodeToString([]byte(url.QueryEscape(string(key))))
	previous := []keys.Entry{
		{Version: keys.Version{ID: solved.ID, Date: "imported"}, Key: encoded, Imported: true, Status: "unknown"},
		{Version: keys.Version{ID: solved.ID, Date: "generated"}, Key: encoded, Status: "exact"},
		{Version: keys.Version{ID: solved.ID, Date: "conflict"}, Key: "41", Imported: true, Status: "unknown"},
		{Version: keys.Version{ID: ambiguous.ID, Date: "ambiguous"}, Key: "41", Imported: true, Status: "unknown"},
		{Version: keys.Version{ID: -2, Date: "not-in-input"}, Key: "42", Imported: true, Status: "unknown"},
	}
	original := append([]keys.Entry(nil), previous...)
	var diagnostics bytes.Buffer
	entries, stats := process(loaded, previous, &diagnostics)
	if !reflect.DeepEqual(previous, original) {
		t.Fatal("processing modified the previous snapshot")
	}
	if len(entries) != 6 || entries[0].Status != "exact" || !entries[0].Imported || entries[0].Key != encoded {
		t.Fatalf("imported key not preserved/confirmed: %+v", entries)
	}
	if !reflect.DeepEqual(entries[1:5], previous[1:5]) {
		t.Fatal("existing generated, conflicting, ambiguous or unmatched entry changed")
	}
	if entries[5].Imported || entries[5].Status != "exact" {
		t.Fatalf("new key metadata: %+v", entries[5])
	}
	decoded, err := keys.Decode(entries[5].Key)
	if err != nil || !bytes.Equal(decoded, key) {
		t.Fatal("new key did not round trip")
	}
	if stats.added != 1 || stats.confirmed != 2 || stats.conflicts != 1 || stats.ambiguous != 1 || stats.failed != 1 || stats.invalid != 2 || stats.plaintext != 1 || stats.beforeCoverage != 4 || stats.afterCoverage != 5 {
		t.Fatalf("unexpected results: %+v", stats)
	}
	if !strings.Contains(diagnostics.String(), "conflicts with existing key") {
		t.Fatal("missing conflict diagnostic")
	}
	var summary bytes.Buffer
	stats.print(&summary, "keys.csv", previous, entries)
	for _, want := range []string{"5/6 (83.33%)", "+1 added", "Status updated to exact: 1", "existing entries unchanged: 4"} {
		if !strings.Contains(summary.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, &summary)
		}
	}
}

func TestRunCreatesInventoryAndIsIdempotent(t *testing.T) {
	solved, _, _ := recoveryFixtures(t)
	dir := t.TempDir()
	mapsPath, keysPath := filepath.Join(dir, "maps.csv"), filepath.Join(dir, "keys.csv")
	file, err := os.Create(mapsPath)
	if err != nil {
		t.Fatal(err)
	}
	writer := csv.NewWriter(file)
	writer.Write(strings.Split("id,date,width,height,backgroundNum,ambianceId,musicId,bOutdoor,capabilities,mapData,canAggro,canUseInventory,canUseObject,canChangeCharac", ","))
	writer.Write([]string{"1", "00123", "15", "17", "0", "0", "0", "false", "0", solved.MapData, "", "", "", ""})
	writer.Flush()
	if err := writer.Error(); err != nil {
		t.Fatal(err)
	}
	file.Close()
	var summary, diagnostics bytes.Buffer
	if err := run(mapsPath, keysPath, &summary, &diagnostics); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), "+1 added") || !bytes.Contains(first, []byte(",false,exact")) {
		t.Fatalf("missing new recovery: %s\n%s", &summary, first)
	}
	summary.Reset()
	if err := run(mapsPath, keysPath, &summary, &diagnostics); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(keysPath)
	if !bytes.Equal(first, second) || !strings.Contains(summary.String(), "+0 added") || !strings.Contains(summary.String(), "Status updated to exact: 0") {
		t.Fatalf("second run changed the inventory: %s", &summary)
	}
	if err := run(mapsPath, mapsPath, &summary, &diagnostics); err == nil {
		t.Fatal("accepted maps file as output")
	}
}

func TestEmptySummary(t *testing.T) {
	var summary bytes.Buffer
	results{}.print(&summary, "keys.csv", nil, nil)
	if strings.Contains(summary.String(), "NaN") || strings.Contains(summary.String(), "Inf") {
		t.Fatal("undefined percentages in empty summary")
	}
}
