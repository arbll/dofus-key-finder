package keys

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestKeyEncoding(t *testing.T) {
	var key []byte
	for i := 32; i <= 127; i++ {
		key = append(key, byte(i))
	}
	got, err := Decode(Encode(key))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("ASCII key round trip: got %q, error %v", got, err)
	}
	// Literal spaces and escaped plus/percent agree with the imported format.
	if got := Encode([]byte(" +%")); got != "20253242253235" {
		t.Fatalf("encoded key = %q", got)
	}
}

func TestInventoryRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.csv")
	if got, err := Load(path); err != nil || len(got) != 0 {
		t.Fatalf("missing inventory: %v, %v", got, err)
	}
	entries := []Entry{
		{Version{4, "00123"}, "2541"},
		{Version{4, "00124"}, Encode([]byte("A%+ "))},
	}
	// Use a valid, noncanonical representation and verify it stays untouched.
	entries[0].Key = "253431" // %41 decodes to A.
	if err := Save(path, entries); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || !reflect.DeepEqual(got, entries) {
		t.Fatalf("inventory round trip: %v, %v", got, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(path, got); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("repeated save changed CSV bytes")
	}
}

func TestLoadRejectsInvalidInventory(t *testing.T) {
	for _, row := range []string{
		"4,001,zz\n",
		"4,001,25\n",
		"4,001,\n",
		"4,001,41\n4,001,42\n",
		"4,001\n",
		"4,001,41,true,unknown\n",
	} {
		path := filepath.Join(t.TempDir(), "keys.csv")
		data := strings.Join(header, ",") + "\n" + row
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("accepted invalid inventory row %q", row)
		}
	}
}

func TestSaveMerged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys_merged.yaml")
	exact := []Entry{{Version{2, "001"}, "253431"}}
	imported := []Entry{{Version{2, "001"}, "42"}, {Version{1, "002"}, "43"}}
	predicted := []Entry{
		{Version{2, "001"}, "44"},
		{Version{1, "002"}, "45"},
		{Version{1, "001"}, "46"},
		{Version{3, "a\"b\nc"}, "47"},
	}
	want := "- id: 1\n  date: \"001\"\n  key: \"46\"\n" +
		"- id: 1\n  date: \"002\"\n  key: \"43\"\n" +
		"- id: 2\n  date: \"001\"\n  key: \"253431\"\n" +
		"- id: 3\n  date: \"a\\\"b\\nc\"\n  key: \"47\"\n"
	for range 2 {
		if err := SaveMerged(path, exact, imported, predicted); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("merged YAML = %s, error %v; want %s", got, err, want)
		}
	}
	if err := SaveMerged(path); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "[]\n" {
		t.Fatalf("empty merged YAML = %q, error %v", got, err)
	}
}
