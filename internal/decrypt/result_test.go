package decrypt

import (
	"errors"
	"slices"
	"testing"

	"github.com/arbll/dofus-key-finder/internal/maps"
)

func TestKeyRecoveryDetails(t *testing.T) {
	loaded, err := maps.Load("../../data/maps.csv.gz")
	if err != nil {
		t.Fatal(err)
	}
	model := train(nil)
	var exact, ambiguous *maps.Map
	for _, m := range loaded {
		result, err := Key(m, nil)
		if err == nil && exact == nil {
			exact = new(maps.Map)
			*exact = m
			if result.UsedPrediction || result.Stats.CandidateCount != "1" || result.Stats.DeterminedBytes != len(result.Key) || result.Stats.AmbiguousBytes != 0 {
				t.Fatalf("bad exact stats: %+v", result)
			}
			if err := model.Observe(m, result.Key); err != nil {
				t.Fatal(err)
			}
		}
		if errors.Is(err, ErrAmbiguous) && ambiguous == nil {
			ambiguous = new(maps.Map)
			*ambiguous = m
		}
		if exact != nil && ambiguous != nil {
			break
		}
	}
	if exact == nil || ambiguous == nil {
		t.Fatal("missing fixtures")
	}
	for _, empty := range []*Model{nil, train(nil)} {
		result, err := Key(*ambiguous, empty)
		if !errors.Is(err, ErrAmbiguous) || result.Key != nil || result.UsedPrediction || result.Stats.AmbiguousBytes == 0 {
			t.Fatalf("bad ambiguous result: %+v, %v", result, err)
		}
	}
	guessed, err := Key(*ambiguous, model)
	if err != nil {
		t.Fatal(err)
	}
	if !guessed.UsedPrediction || guessed.Stats.KeyLength != len(guessed.Key) || guessed.Stats.DeterminedBytes+guessed.Stats.AmbiguousBytes != len(guessed.Key) {
		t.Fatalf("bad predicted stats: %+v", guessed)
	}
	candidates, err := candidates(*ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	for i, k := range rotate(guessed.Key) {
		if !slices.Contains(candidates[i], k) {
			t.Fatal("prediction escaped solver constraints")
		}
	}
	result, err := Key(*exact, model)
	if err != nil || result.UsedPrediction {
		t.Fatalf("model used for exact map: %+v, %v", result, err)
	}
	before := *model
	if err := model.Observe(*exact, []byte("bad")); err == nil {
		t.Fatal("accepted incompatible training key")
	}
	if *model != before {
		t.Fatal("invalid training mutated model")
	}
}
