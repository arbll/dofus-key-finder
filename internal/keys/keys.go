// Package keys reads and writes the key inventory, indexed by map ID and date.
package keys

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type Version struct {
	ID   int
	Date string
}

type Entry struct {
	Version
	Key      string // Original hex-encoded, URL-escaped representation.
	Imported bool
	Status   string
}

var header = []string{"id", "date", "key", "imported", "status"}

// Decode returns the unescaped key bytes used by the cipher.
func Decode(encoded string) ([]byte, error) {
	escaped, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	key, err := url.QueryUnescape(string(escaped))
	if err != nil {
		return nil, err
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("empty key")
	}
	return []byte(key), nil
}

// Encode matches the existing wire format: percent and plus must be escaped
// before hex encoding. Other ASCII key bytes retain their original values.
func Encode(key []byte) string {
	escaped := strings.NewReplacer("%", "%25", "+", "%2B").Replace(string(key))
	return hex.EncodeToString([]byte(escaped))
}

// Load treats a missing inventory as empty, so the CLI can start from scratch.
func Load(path string) ([]Entry, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	columns, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read keys header: %w", err)
	}
	if !slices.Equal(columns, header) {
		return nil, fmt.Errorf("unexpected keys header: %v; want %v", columns, header)
	}
	var entries []Entry
	seen := make(map[Version]bool)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read keys row: %w", err)
		}
		line, _ := reader.FieldPos(0)
		id, err := strconv.Atoi(row[0])
		if err != nil {
			return nil, fmt.Errorf("keys line %d: invalid ID: %w", line, err)
		}
		imported, err := strconv.ParseBool(row[3])
		if err != nil {
			return nil, fmt.Errorf("keys line %d: invalid imported flag: %w", line, err)
		}
		if _, err := Decode(row[2]); err != nil {
			return nil, fmt.Errorf("keys line %d: invalid key: %w", line, err)
		}
		entry := Entry{Version{id, row[1]}, row[2], imported, row[4]}
		if seen[entry.Version] {
			return nil, fmt.Errorf("keys line %d: duplicate map %d (%s)", line, id, entry.Date)
		}
		seen[entry.Version] = true
		entries = append(entries, entry)
	}
	return entries, nil
}

// Save atomically replaces the inventory only after the entire CSV is written.
// Existing ordering is supplied by the caller; CRLF matches the source CSV.
func Save(path string, entries []Entry) error {
	mode := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".keys-*.csv")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	writer.UseCRLF = true
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, entry := range entries {
		if err := writer.Write([]string{strconv.Itoa(entry.ID), entry.Date, entry.Key, strconv.FormatBool(entry.Imported), entry.Status}); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
