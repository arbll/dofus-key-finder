package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const SampleSize int = 10

func findPossibleKeyLengthsWorker(probabilityByPosition []map[byte]float64, jobs <-chan mapData, results chan<- []int) {
	for j := range jobs {
		result := findPossibleKeyLengths(j, probabilityByPosition)
		results <- result
	}
}

func TestBenchmarkLength(t *testing.T) {
	db := connect()
	mapsData := getKnownMapsData(db)
	probabilityByPosition := getValuesProbabilityByPosition(mapsData)

	mapCount := len(mapsData)
	results := make(chan []int, mapCount)
	jobs := make(chan mapData, mapCount)

	for w := 0; w < 8; w++ {
		go findPossibleKeyLengthsWorker(probabilityByPosition, jobs, results)
	}

	for i := 0; i < SampleSize; i++ {
		jobs <- mapsData[i]
	}

	close(jobs)

	okLengths, badLengths, noLengths := 0, 0, 0

	for i := 0; i < SampleSize; i++ {
		lengths := <-results
		switch len(lengths) {
		case 0:
			noLengths++
		case 1:
			okLengths++
		case 2:
			if lengths[0]*2 == lengths[1] {
				okLengths++
			} else {
				badLengths++
			}
		default:
			badLengths++
		}
	}

	t.Logf("Results : %d ok (%f%%), %d not found (%f%%), %d multiple found (%f%%)\n", okLengths, float32(okLengths)/float32(SampleSize)*100, noLengths, float32(noLengths)/float32(SampleSize)*100, badLengths, float32(badLengths)/float32(SampleSize)*100)
	assert.Equal(t, 0, noLengths, "The algorithm was not able to resolve some keys. The problem is probably comming from the data.")
}
