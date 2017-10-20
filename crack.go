package main

import (
	"log"
)

func main() {
	db := connect()
	mapsData := getKnownMapsData(db)
	for i := 0; i < 100; i++ {
		findPossibleDecryptedData(mapsData[i], mapsData)
	}
}

func findPossibleKeyLengths(targetMap mapData, valuesByPosition [][]byte) []int {
	possibleKeyLengths := []int{}
	for i := KEY_SIZE_MIN; i < KEY_SIZE_MAX; i++ {
		if keyLengthIsPossible(i, targetMap, valuesByPosition) {
			possibleKeyLengths = append(possibleKeyLengths, i)
		}
	}
	return possibleKeyLengths
}

func findFirstPossibleKeyLength(targetMap mapData, valuesByPosition [][]byte) int {
	for i := KEY_SIZE_MIN; i < KEY_SIZE_MAX; i++ {
		if keyLengthIsPossible(i, targetMap, valuesByPosition) {
			return i
		}
	}
	return 0
}

func keyLengthIsPossible(keyLength int, targetMap mapData, valuesByPosition [][]byte) bool {
	data := decodeBase16(targetMap.data)
	for i := 0; i < keyLength; i++ {
		for j := i; j+keyLength < len(data); j += keyLength {
			position1 := j % CELL_SIZE
			position2 := (j + keyLength) % CELL_SIZE
			valuesForXoredPositions := getXoredValuesForPositions(position1, position2, valuesByPosition)
			xoredValue := data[j] ^ data[j+keyLength]
			if !containsValue(valuesForXoredPositions, xoredValue) {
				return false
			}
		}
	}
	return true
}

func findPossibleDecryptedData(targetMap mapData, mapsData []mapData) [][]byte {
	log.Println("Finding decrypted data for ", targetMap.id)

	valuesByPosition := getValuesByPosition(mapsData)

	keyLength := findFirstPossibleKeyLength(targetMap, valuesByPosition)
	log.Println("Found keyLength:", keyLength)

	data := decodeBase16(targetMap.data)
	decryptedData := initializeDecryptedData(len(data), valuesByPosition)

	decryptedData = eliminateImpossibleValuesForDecryptedData(data, keyLength, decryptedData, valuesByPosition)
	log.Println("Decryption percent : ", decryptionPercent(keyLength, decryptedData), "%")
	return decryptedData
}

func initializeDecryptedData(dataLength int, valuesByPosition [][]byte) [][]byte {
	decryptedData := make([][]byte, dataLength)
	for i := 0; i < dataLength; i++ {
		decryptedData[i] = make([]byte, len(valuesByPosition[i%CELL_SIZE]))
		copy(decryptedData[i], valuesByPosition[i%CELL_SIZE])
	}
	return decryptedData
}

func eliminateImpossibleValuesForDecryptedData(mapData []byte, keyLength int, decryptedData [][]byte, valuesByPosition [][]byte) [][]byte {
	dataLength := len(mapData)
	for i := 0; i < dataLength; i++ {
		keyOffset := i % keyLength
		for j := keyOffset; j < dataLength; j += keyLength {
			if j == i {
				continue
			}
			xoredValue := mapData[i] ^ mapData[j]
			possibleValues := getPossibleValuesAtPositionFromXoredValue(xoredValue, decryptedData[i], decryptedData[j])
			decryptedData[i] = intersectValues(possibleValues, decryptedData[i])
		}
	}
	return decryptedData
}

func intersectValues(values1 []byte, values2 []byte) []byte {
	intersect := []byte{}
	for _, v1 := range values1 {
		for _, v2 := range values1 {
			if v1 == v2 {
				intersect = append(intersect, v1)
			}
		}
	}
	return intersect
}

func decryptionPercent(keyLength int, decryptedData [][]byte) float64 {
	foundKeyParts := make([]bool, keyLength)
	for i := range foundKeyParts {
		foundKeyParts[i] = false
	}

	for i := 0; i < len(decryptedData); i++ {
		if len(decryptedData[i]) == 1 {
			foundKeyParts[i%keyLength] = true
		}
	}

	count := 0
	for i := range foundKeyParts {
		if foundKeyParts[i] {
			count++
		}
	}
	return float64(count) / float64(keyLength) * 100
}
