package dfkey

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

const ProcCount int = 8
const SampleSize int = 100
const ConnectString string = "root:@/AMPS"

func findPossibleKeyLengthsWorker(valuesByPosition [][]byte, jobs <-chan MapData, results chan<- []int) {
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

func findPossibleDecryptedDataWorker(mapsData []MapData, jobs <-chan MapData, results chan<- FindPossibleDecryptedDataResult) {
	for j := range jobs {
		mapData := decodeBase16(j.data)
		decryptedData, keyLength := findPossibleDecryptedDataAndKeyLength(mapData, mapsData)
		results <- FindPossibleDecryptedDataResult{decryptedData, keyLength}
	}
}

func checkGuessKeyDataWorker(mapsData []MapData, jobs <-chan MapData, results chan<- int) {
	for j := range jobs {
		if j.key != "" {
			key := GuessKey(j, mapsData)
			if len(key) > 0 {
				if hex.EncodeToString(key) == j.key {
					results <- 1
				} else {
					results <- 0
				}
			}
		}
		results <- -1
	}
}

func TestBenchmarkLength(t *testing.T) {
	db := ConnectDB(ConnectString)
	mapsData := GetKnownMapsData(db)
	valuesByPosition := getValuesByPosition(mapsData)

	results := make(chan []int, SampleSize)
	jobs := make(chan MapData, SampleSize)

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
	db := ConnectDB(ConnectString)
	mapsData := GetKnownMapsData(db)

	results := make(chan FindPossibleDecryptedDataResult, SampleSize)
	jobs := make(chan MapData, SampleSize)

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

func TestBenchmarkGuessKey(t *testing.T) {
	db := ConnectDB(ConnectString)
	mapsData := GetKnownMapsData(db)

	results := make(chan int, SampleSize)
	jobs := make(chan MapData, SampleSize)

	for w := 0; w < ProcCount; w++ {
		go checkGuessKeyDataWorker(mapsData, jobs, results)
	}

	for i := 0; i < SampleSize; i++ {
		jobs <- mapsData[i]
	}

	close(jobs)

	goodCount := 0
	badCount := 0
	for i := 0; i < SampleSize; i++ {
		result := <-results
		switch result {
		case 0:
			badCount++
		case 1:
			goodCount++
		default:
		}
	}

	t.Logf("Result for guessKey: %f%% good, %f%% bad", float64(goodCount)/float64(goodCount+badCount)*100, float64(badCount)/float64(goodCount+badCount)*100)
	assert.Equal(t, 0, badCount)
}
