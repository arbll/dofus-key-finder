package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const ProcCount int = 8
const SampleSize int = 100

func findPossibleKeyLengthsWorker(valuesByPosition [][]byte, jobs <-chan mapData, results chan<- []int) {
	for j := range jobs {
		mapData := decodeBase16(j.data)
		result := findPossibleKeyLengths(mapData, valuesByPosition)
		results <- result
	}
}

type FindPossibleDecryptedDataResult struct {
	decryptedData [][]byte
	keyLength     int
}

func findPossibleDecryptedDataWorker(mapsData []mapData, jobs <-chan mapData, results chan<- FindPossibleDecryptedDataResult) {
	for j := range jobs {
		mapData := decodeBase16(j.data)
		decryptedData, keyLength := findPossibleDecryptedDataAndKeyLength(mapData, mapsData)
		results <- FindPossibleDecryptedDataResult{decryptedData, keyLength}
	}
}

func TestBenchmarkLength(t *testing.T) {
	db := connect()
	mapsData := getKnownMapsData(db)
	valuesByPosition := getValuesByPosition(mapsData)

	results := make(chan []int, SampleSize)
	jobs := make(chan mapData, SampleSize)

	for w := 0; w < ProcCount; w++ {
		go findPossibleKeyLengthsWorker(valuesByPosition, jobs, results)
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

func TestBenchmarkDecryptData(t *testing.T) {
	db := connect()
	mapsData := getKnownMapsData(db)

	results := make(chan FindPossibleDecryptedDataResult, SampleSize)
	jobs := make(chan mapData, SampleSize)

	for w := 0; w < ProcCount; w++ {
		go findPossibleDecryptedDataWorker(mapsData, jobs, results)
	}

	for i := 0; i < SampleSize; i++ {
		jobs <- mapsData[i]
	}

	close(jobs)
	sumPercentByKeyType := [10]float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	countByKeyType := [10]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < SampleSize; i++ {
		result := <-results
		percent := decryptionPercent(result.keyLength, result.decryptedData)
		sumPercentByKeyType[result.keyLength%10] += percent
		countByKeyType[result.keyLength%10]++
	}
	for i := 0; i < 10; i++ {
		t.Logf("Result for keyType %d: mean(%f)", i, sumPercentByKeyType[i]/float64(countByKeyType[i]))
	}
}
