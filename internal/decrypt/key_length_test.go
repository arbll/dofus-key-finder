package decrypt

import (
	"errors"
	"fmt"
	"testing"

	"github.com/arbll/dofus-key-finder/internal/maps"
)

// Key lengths come from https://github.com/Daweyy/MapKeys-DR/tree/main/maps.
func TestKnownMapKeyLengths(t *testing.T) {
	known := map[string]int{
		"48_0706131721":  129,
		"305_0706131721": 191,
		"369_0706131721": 240,
		"478_0706131721": 256,
		"845_0706131721": 128,
	}
	loaded, err := maps.Load("../../data/maps.csv")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range loaded {
		name := fmt.Sprintf("%d_%s", m.ID, m.Date)
		want, ok := known[name]
		if !ok {
			continue
		}
		got, err := KeyLength(m)
		if err != nil {
			t.Errorf("map %s: %v", name, err)
		} else if got != want {
			t.Errorf("map %s: key length = %d, want %d", name, got, want)
		}
		delete(known, name)
	}
	if len(known) != 0 {
		t.Errorf("known maps missing from CSV: %v", known)
	}
}

func TestKeyLengthRejectsShortAndInvalidData(t *testing.T) {
	_, err := KeyLength(maps.Map{ID: 1, MapData: "not hex"})
	if err == nil {
		t.Fatal("expected invalid hexadecimal data error")
	}
	_, err = KeyLength(maps.Map{ID: 1, MapData: "00"})
	if err == nil || errors.Is(err, ErrNoKeyLength) {
		t.Fatalf("short data error = %v", err)
	}
}
