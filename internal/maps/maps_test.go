package maps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testHeader = "id,date,width,height,backgroundNum,ambianceId,musicId,bOutdoor,capabilities,mapData,canAggro,canUseInventory,canUseObject,canChangeCharac\n"

func writeCSV(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "maps.csv")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad(t *testing.T) {
	path := writeCSV(t, testHeader+
		"4,0609111108,15,17,0,0,118,false,0,first,,,,\n"+
		"4,0706131721,19,22,71,6,115,1,231,second,true,false,true,false\n")

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d maps, want 2", len(loaded))
	}
	if loaded[0].ID != 4 || loaded[1].ID != 4 {
		t.Fatalf("duplicate map IDs were not preserved: %v, %v", loaded[0].ID, loaded[1].ID)
	}
	if loaded[0].Date != "0609111108" || loaded[0].Outdoor || loaded[0].CanAggro != nil {
		t.Fatalf("first map lost CSV values: %+v", loaded[0])
	}
	second := loaded[1]
	if second.Width != 19 || second.Height != 22 || second.BackgroundNum != 71 ||
		second.AmbianceID != 6 || second.MusicID != 115 || !second.Outdoor ||
		second.Capabilities != 231 || second.MapData != "second" {
		t.Fatalf("second map has incorrect fields: %+v", second)
	}
	if second.CanAggro == nil || !*second.CanAggro ||
		second.CanUseInventory == nil || *second.CanUseInventory ||
		second.CanUseObject == nil || !*second.CanUseObject ||
		second.CanChangeCharac == nil || *second.CanChangeCharac {
		t.Fatalf("second map has incorrect optional flags: %+v", second)
	}
}

func TestLoadReportsInvalidField(t *testing.T) {
	path := writeCSV(t, testHeader+"4,0609111108,invalid,17,0,0,118,false,0,first,,,,\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "line 2, width") {
		t.Fatalf("Load() error = %v, want line and field", err)
	}
}
