package decrypt

import (
	"bytes"
	"github.com/arbll/dofus-key-finder/internal/maps"
	"testing"
)

func TestGuessPreservesConstraintsAndRotation(t *testing.T) {
	plain := bytes.Repeat([]byte("bhaaiaaaaa"), 100)
	aligned := []byte("Q%+abcXYZ_")
	data := make([]byte, len(plain))
	for i, b := range plain {
		data[i] = b ^ aligned[i%len(aligned)]
	}
	candidates := make([][]byte, len(aligned))
	for i, k := range aligned {
		candidates[i] = []byte{k ^ 1, k}
	}
	candidates[0] = []byte{aligned[0]}
	model := train([][]byte{plain})
	{
		got, err := model.guess(data, candidates)
		if err != nil {
			t.Fatal(err)
		}
		rotated := rotate(got)
		if rotated[0] != aligned[0] {
			t.Fatal("changed singleton")
		}
		for i, b := range rotated {
			if !bytes.Contains(candidates[i], []byte{b}) {
				t.Fatal("escaped candidate constraints")
			}
		}
		if !bytes.Equal(rotated, aligned) {
			t.Fatalf("got %q want %q", rotated, aligned)
		}
	}
	if _, err := model.guess(data, nil); err == nil {
		t.Fatal("accepted empty candidates")
	}
	if _, err := model.guess(data, [][]byte{{}}); err == nil {
		t.Fatal("accepted empty choices")
	}

}

func TestPositionUsesCellPosition(t *testing.T) {
	// Globally, 'a' dominates; at position zero, 'b' is certain.
	m := train([][]byte{bytes.Repeat([]byte("baaaaaaaaa"), 100)})
	data := []byte{'b' ^ 40}
	c := [][]byte{{40, 'b' ^ 40 ^ 'a'}}
	position, _ := m.guess(data, c)
	if position[0] != 40 {
		t.Fatalf("position %v", position)
	}
}

func TestGroupedSplitTransitiveAndRepeatable(t *testing.T) {
	s := []sample{
		{m: maps.Map{ID: 1, Date: "a"}, plain: []byte("one")},
		{m: maps.Map{ID: 1, Date: "b"}, plain: []byte("two")},
		{m: maps.Map{ID: 2}, plain: []byte("two")},
		{m: maps.Map{ID: 3}, plain: []byte("three")},
	}
	splitSamples(s)
	for i := 1; i < 3; i++ {
		if s[i].split != s[0].split {
			t.Fatal("related samples leaked across partitions")
		}
	}
	want := s[0].split
	splitSamples(s)
	if s[0].split != want {
		t.Fatal("split not reproducible")
	}
}
