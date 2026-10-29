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
	"slices"
	"strings"
	"testing"

	"github.com/arbll/dofus-key-finder/internal/decrypt"
	"github.com/arbll/dofus-key-finder/internal/keys"
	"github.com/arbll/dofus-key-finder/internal/maps"
)

// Exercise the actual solver using real map data, independent of the key inventories.
func recoveryFixtures(t *testing.T) (maps.Map, []byte, maps.Map) {
	t.Helper()
	loaded, err := maps.Load("../../data/maps.csv.gz")
	if err != nil {
		t.Fatal(err)
	}
	var solved, ambiguous maps.Map
	var recovered []byte
	for _, m := range loaded {
		if _, err := m.EncryptedData(); err != nil {
			continue
		}
		key, err := decrypt.Key(m, nil)
		if err == nil && recovered == nil {
			solved, recovered = m, key.Key
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
	previous := inventory{
		imported: []keys.Entry{
			{Version: keys.Version{ID: solved.ID, Date: "imported"}, Key: encoded},
			{Version: keys.Version{ID: solved.ID, Date: "conflict"}, Key: "41"},
			{Version: keys.Version{ID: ambiguous.ID, Date: "ambiguous"}, Key: "41"},
			{Version: keys.Version{ID: -2, Date: "not-in-input"}, Key: "42"},
		},
		exact: []keys.Entry{{Version: keys.Version{ID: solved.ID, Date: "generated"}, Key: encoded}},
	}
	originalImported := append([]keys.Entry(nil), previous.imported...)
	originalExact := append([]keys.Entry(nil), previous.exact...)
	var diagnostics bytes.Buffer
	entries, stats := process(loaded, previous, &diagnostics)
	if !reflect.DeepEqual(entries.imported, originalImported) || !reflect.DeepEqual(previous.imported, originalImported) || !reflect.DeepEqual(previous.exact, originalExact) {
		t.Fatal("processing changed imported keys or the previous snapshot")
	}
	if len(entries.exact) != 4 || entries.exact[0] != originalExact[0] {
		t.Fatalf("unexpected exact keys: %+v", entries.exact)
	}
	for _, entry := range entries.exact {
		decoded, err := keys.Decode(entry.Key)
		if err != nil || !bytes.Equal(decoded, key) {
			t.Fatal("exact inventory did not contain recovered key")
		}
	}
	if stats.added != 3 || stats.confirmed != 2 || stats.conflicts != 1 || stats.ambiguous != 1 || stats.failed != 1 || stats.invalid != 2 || stats.plaintext != 1 || stats.beforeCoverage != 4 || stats.afterCoverage != 5 {
		t.Fatalf("unexpected results: %+v", stats)
	}
	if stats.exactCovered != 4 || stats.importedOnly != 1 || stats.predictedOnly != 0 || stats.missing != 1 || stats.noKeyLength != 1 || stats.solverErrors != 0 || stats.unknownAmbiguity != [4]int{} {
		t.Fatalf("incorrect final coverage or unknown-map statistics: %+v", stats)
	}
	if !strings.Contains(diagnostics.String(), "conflicts with existing key") {
		t.Fatal("missing conflict diagnostic")
	}
	var summary bytes.Buffer
	stats.print(&summary, entries, true)
	for _, want := range []string{"5/6 (83.33%)", "+3 added", "4 imported / 4 exact / 0 predicted", "(+1 versions)"} {
		if !strings.Contains(summary.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, &summary)
		}
	}
}

func TestRunCreatesInventoryAndIsIdempotent(t *testing.T) {
	solved, key, _ := recoveryFixtures(t)
	dir := t.TempDir()
	mapsPath := filepath.Join(dir, "maps.csv")
	paths := inventoryPaths{filepath.Join(dir, "imported.csv"), filepath.Join(dir, "exact.csv"), filepath.Join(dir, "predicted.csv")}
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
	if err := keys.Save(paths.imported, []keys.Entry{{Version: keys.Version{ID: 1, Date: "00123"}, Key: keys.Encode(key)}}); err != nil {
		t.Fatal(err)
	}
	importedBefore, _ := os.ReadFile(paths.imported)
	if err := run(mapsPath, paths, &summary, &diagnostics, false, false); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(paths.exact)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), "+1 added") || !bytes.HasPrefix(first, []byte("id,date,key\r\n")) {
		t.Fatalf("missing new recovery: %s\n%s", &summary, first)
	}
	summary.Reset()
	if err := run(mapsPath, paths, &summary, &diagnostics, false, true); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(paths.exact)
	importedAfter, _ := os.ReadFile(paths.imported)
	if !bytes.Equal(importedBefore, importedAfter) || !strings.Contains(summary.String(), "1/1 (100.00%)") {
		t.Fatal("imported data or deduplicated coverage changed")
	}
	if !bytes.Equal(first, second) || !strings.Contains(summary.String(), "+0 added") {
		t.Fatalf("second run changed the inventory: %s", &summary)
	}
	paths.exact = mapsPath
	if err := run(mapsPath, paths, &summary, &diagnostics, false, false); err == nil {
		t.Fatal("accepted maps file as output")
	}
}

func TestEmptySummary(t *testing.T) {
	var summary bytes.Buffer
	results{}.print(&summary, inventory{}, false)
	if strings.Contains(summary.String(), "NaN") || strings.Contains(summary.String(), "Inf") {
		t.Fatal("undefined percentages in empty summary")
	}
}

func TestPredictionsPromotedByExactRecovery(t *testing.T) {
	solved, key, ambiguous := recoveryFixtures(t)
	matched, wrong := solved, solved
	matched.Date, wrong.Date, ambiguous.Date = "matched", "wrong", "ambiguous"
	previous := inventory{predicted: []keys.Entry{
		{Version: keys.Version{ID: matched.ID, Date: matched.Date}, Key: keys.Encode(key)},
		{Version: keys.Version{ID: wrong.ID, Date: wrong.Date}, Key: "41"},
		{Version: keys.Version{ID: ambiguous.ID, Date: ambiguous.Date}, Key: "42"},
	}}
	var diagnostics bytes.Buffer
	entries, stats := process([]maps.Map{matched, wrong, ambiguous}, previous, &diagnostics)
	if stats.promoted != 2 || stats.corrected != 1 || stats.added != 0 || stats.beforeCoverage != 0 || stats.afterCoverage != 2 {
		t.Fatalf("unexpected results: %+v", stats)
	}
	if stats.exactCovered != 2 || stats.predictedOnly != 1 || stats.changedPredictions != 1 || stats.preserved != 0 {
		t.Fatalf("promotions counted as preserved predictions: %+v", stats)
	}
	if len(entries.exact) != 2 || entries.predicted[0].Version != previous.predicted[2].Version || len(previous.predicted) != 3 {
		t.Fatalf("unexpected inventories: %+v", entries)
	}
	for _, entry := range entries.exact {
		got, err := keys.Decode(entry.Key)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatal("promotion did not use recovered key")
		}
	}
	if !strings.Contains(diagnostics.String(), "prediction differs") {
		t.Fatal("missing correction diagnostic")
	}
}

func TestRunRejectsPredictionsOverlappingTrustedInventories(t *testing.T) {
	dir := t.TempDir()
	paths := inventoryPaths{filepath.Join(dir, "imported.csv"), filepath.Join(dir, "exact.csv"), filepath.Join(dir, "predicted.csv")}
	entry := []keys.Entry{{Version: keys.Version{ID: 1, Date: "001"}, Key: "41"}}
	for _, path := range []string{paths.imported, paths.predicted} {
		if err := keys.Save(path, entry); err != nil {
			t.Fatal(err)
		}
	}
	mapsPath := filepath.Join(dir, "maps.csv")
	if err := os.WriteFile(mapsPath, []byte("id,date,width,height,backgroundNum,ambianceId,musicId,bOutdoor,capabilities,mapData,canAggro,canUseInventory,canUseObject,canChangeCharac\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(paths.exact)
	err := run(mapsPath, paths, &bytes.Buffer{}, &bytes.Buffer{}, false, false)
	if err == nil || !strings.Contains(err.Error(), "duplicate map") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
	after, _ := os.ReadFile(paths.exact)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid input modified inventory")
	}
}

func TestUnifiedPredictionAndIdempotence(t *testing.T) {
	solved, _, ambiguous := recoveryFixtures(t)
	solved.ID, ambiguous.ID = 1, 1
	solved.Date, ambiguous.Date = "exact", "prediction"
	var diagnostics bytes.Buffer
	loaded := []maps.Map{solved, ambiguous}
	entries, stats := process(loaded, inventory{}, &diagnostics)
	if len(entries.exact) != 1 || len(entries.predicted) != 1 || stats.predicted != 1 || stats.trained != 1 || stats.afterCoverage != 1 {
		t.Fatalf("unexpected result: %+v, %s", stats, &diagnostics)
	}
	if entries.predicted[0].Version != (keys.Version{ID: ambiguous.ID, Date: ambiguous.Date}) {
		t.Fatal("prediction misrouted")
	}
	ambiguousMaps := 0
	for _, count := range stats.unknownAmbiguity {
		ambiguousMaps += count
	}
	if stats.uniqueIDs != 1 || stats.exactCovered != 1 || stats.predictedOnly != 1 || stats.missing != 0 || stats.newPredictions != 1 || ambiguousMaps != 1 {
		t.Fatalf("incorrect coverage or new prediction count: %+v", stats)
	}
	again, stats := process(loaded, entries, &diagnostics)
	if !reflect.DeepEqual(entries, again) || stats.promoted != 0 {
		t.Fatal("second run changed inventories")
	}
	if stats.newPredictions != 0 || stats.changedPredictions != 0 || stats.unchangedPredictions != 1 || stats.preserved != 0 || stats.afterCoverage != stats.beforeCoverage {
		t.Fatalf("unchanged prediction counted as a change: %+v", stats)
	}
	changed := inventory{exact: entries.exact, predicted: slices.Clone(entries.predicted)}
	changed.predicted[0].Key = "41"
	refreshed, stats := process(loaded, changed, &diagnostics)
	if !reflect.DeepEqual(entries, refreshed) || stats.changedPredictions != 1 || stats.newPredictions != 0 || stats.unchangedPredictions != 0 {
		t.Fatalf("changed prediction was not reported: %+v", stats)
	}
	// Predictions cannot train themselves when no known or exact key is available.
	onlyPrediction, stats := process([]maps.Map{ambiguous}, inventory{predicted: entries.predicted}, &diagnostics)
	if stats.trained != 0 || stats.predicted != 0 || !reflect.DeepEqual(onlyPrediction.predicted, entries.predicted) {
		t.Fatal("prediction entered training")
	}
	if stats.preserved != 1 || stats.noTraining != 1 || stats.predictedOnly != 1 || stats.missing != 0 {
		t.Fatalf("preserved prediction was not reported: %+v", stats)
	}
	_, stats = process([]maps.Map{ambiguous}, inventory{}, &diagnostics)
	if stats.noTraining != 1 || stats.missing != 1 || stats.predictedOnly != 0 || stats.preserved != 0 {
		t.Fatalf("map without a key or training data was not reported as missing: %+v", stats)
	}
}

func TestProcessReportsFailuresAndPreservedPredictions(t *testing.T) {
	loaded := []maps.Map{
		{ID: 1, MapData: "!"},
		{ID: 2, MapData: ""},
		{ID: 3, MapData: "00"},
		{ID: 4, MapData: strings.Repeat("ff", 300)},
	}
	previous := inventory{predicted: []keys.Entry{
		{Version: keys.Version{ID: 1}, Key: "41"},
		{Version: keys.Version{ID: 4}, Key: "41"},
		{Version: keys.Version{ID: 99}, Key: "41"},
	}}
	var diagnostics bytes.Buffer
	entries, stats := process(loaded, previous, &diagnostics)
	if !reflect.DeepEqual(entries.predicted, previous.predicted) || stats.preserved != 3 {
		t.Fatalf("predictions for invalid, failed, or absent maps were not preserved: %+v", stats)
	}
	if stats.total != 4 || stats.uniqueIDs != 4 || stats.invalid != 2 || stats.encrypted != 2 || stats.failed != 2 || stats.noKeyLength != 1 || stats.solverErrors != 1 || stats.predictionErrors != 0 {
		t.Fatalf("incorrect failure breakdown: %+v", stats)
	}
	if stats.predictedOnly != 1 || stats.missing != 1 || stats.exactCovered != 0 || stats.importedOnly != 0 || stats.unknownAmbiguity != [4]int{} {
		t.Fatalf("inventory entries outside encrypted input affected coverage: %+v", stats)
	}
}

func TestRunRejectsAliasedInventory(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "maps.csv")
	alias := filepath.Join(dir, "keys_exact.csv")
	if err := os.WriteFile(source, []byte("preserve me"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, alias); err != nil {
		t.Fatal(err)
	}
	err := run(source, inventoryPaths{filepath.Join(dir, "keys_imported.csv"), alias, filepath.Join(dir, "keys_predicted.csv")}, &bytes.Buffer{}, &bytes.Buffer{}, false, false)
	if err == nil || !strings.Contains(err.Error(), "different files") {
		t.Fatalf("expected alias rejection, got %v", err)
	}
	got, err := os.ReadFile(source)
	if err != nil || string(got) != "preserve me" {
		t.Fatal("input modified")
	}
}
