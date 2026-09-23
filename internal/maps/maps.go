package maps

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
)

// Map is one row of the maps CSV. Date is a string to preserve leading zeroes.
// The optional flags are nil when their CSV fields are empty.
type Map struct {
	ID              int
	Date            string
	Width           int
	Height          int
	BackgroundNum   int
	AmbianceID      int
	MusicID         int
	Outdoor         bool
	Capabilities    int
	MapData         string
	CanAggro        *bool
	CanUseInventory *bool
	CanUseObject    *bool
	CanChangeCharac *bool
}

var header = []string{
	"id", "date", "width", "height", "backgroundNum", "ambianceId", "musicId",
	"bOutdoor", "capabilities", "mapData", "canAggro", "canUseInventory",
	"canUseObject", "canChangeCharac",
}

// Load reads maps from a CSV file, preserving every row in file order.
func Load(path string) ([]Map, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open maps CSV %q: %w", path, err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.ReuseRecord = true
	columns, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read maps CSV header: %w", err)
	}
	if len(columns) != len(header) {
		return nil, fmt.Errorf("maps CSV header has %d columns, want %d", len(columns), len(header))
	}
	for i, name := range header {
		if columns[i] != name {
			return nil, fmt.Errorf("maps CSV column %d is %q, want %q", i+1, columns[i], name)
		}
	}

	var result []Map
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read maps CSV row: %w", err)
		}
		line, _ := reader.FieldPos(0)
		m, err := parseMap(record, line)
		if err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, nil
}

func parseMap(record []string, line int) (Map, error) {
	var m Map
	var err error
	parseInt := func(index int) (int, error) {
		value, err := strconv.Atoi(record[index])
		if err != nil {
			return 0, fmt.Errorf("maps CSV line %d, %s: %w", line, header[index], err)
		}
		return value, nil
	}
	parseBool := func(index int) (bool, error) {
		value, err := strconv.ParseBool(record[index])
		if err != nil {
			return false, fmt.Errorf("maps CSV line %d, %s: %w", line, header[index], err)
		}
		return value, nil
	}
	parseOptionalBool := func(index int) (*bool, error) {
		if record[index] == "" {
			return nil, nil
		}
		value, err := parseBool(index)
		return &value, err
	}

	if m.ID, err = parseInt(0); err != nil {
		return Map{}, err
	}
	m.Date = record[1]
	if m.Width, err = parseInt(2); err != nil {
		return Map{}, err
	}
	if m.Height, err = parseInt(3); err != nil {
		return Map{}, err
	}
	if m.BackgroundNum, err = parseInt(4); err != nil {
		return Map{}, err
	}
	if m.AmbianceID, err = parseInt(5); err != nil {
		return Map{}, err
	}
	if m.MusicID, err = parseInt(6); err != nil {
		return Map{}, err
	}
	if m.Outdoor, err = parseBool(7); err != nil {
		return Map{}, err
	}
	if m.Capabilities, err = parseInt(8); err != nil {
		return Map{}, err
	}
	m.MapData = record[9]
	if m.CanAggro, err = parseOptionalBool(10); err != nil {
		return Map{}, err
	}
	if m.CanUseInventory, err = parseOptionalBool(11); err != nil {
		return Map{}, err
	}
	if m.CanUseObject, err = parseOptionalBool(12); err != nil {
		return Map{}, err
	}
	if m.CanChangeCharac, err = parseOptionalBool(13); err != nil {
		return Map{}, err
	}
	return m, nil
}
