package main

import (
	"encoding/hex"
	"fmt"
)

func main() {
	db := connect()
	mapsData := getKnownMapsData(db)
	fmt.Println(hex.EncodeToString(guessKey(mapsData[1], mapsData)) == mapsData[1].key)
}

func guessKey(targetMap mapData, mapsData []mapData) []byte {
	mapData := decodeBase16(targetMap.data)
	decryptedData, keyLength := findPossibleDecryptedDataAndKeyLength(mapData, mapsData)
	decryptionPercent := decryptionPercent(keyLength, decryptedData)
	fmt.Printf("Map(%d): %f%% of the key found. length: (%d) type: (%d)\n", targetMap.id, decryptionPercent, keyLength, keyLength%CellSize)
	if decryptionPercent == 100 {
		return decryptedDataToKey(mapData, keyLength, decryptedData)
	}
	return []byte{}
}

func findPossibleKeyLengths(mapData []byte, valuesByPosition [][]byte) []int {
	possibleKeyLengths := []int{}
	for i := KeySizeMin; i < KeySizeMax; i++ {
		if keyLengthIsPossible(i, mapData, valuesByPosition) {
			possibleKeyLengths = append(possibleKeyLengths, i)
		}
	}
	return possibleKeyLengths
}

func findFirstPossibleKeyLength(mapData []byte, valuesByPosition [][]byte) int {
	for i := KeySizeMin; i < KeySizeMax; i++ {
		if keyLengthIsPossible(i, mapData, valuesByPosition) {
			return i
		}
	}
	return 0
}

func keyLengthIsPossible(keyLength int, mapData []byte, valuesByPosition [][]byte) bool {
	for i := 0; i < keyLength; i++ {
		for j := i; j+keyLength < len(mapData); j += keyLength {
			position1 := j % CellSize
			position2 := (j + keyLength) % CellSize
			valuesForXoredPositions := getXoredValuesForPositions(position1, position2, valuesByPosition)
			xoredValue := mapData[j] ^ mapData[j+keyLength]
			if !containsValue(valuesForXoredPositions, xoredValue) {
				return false
			}
		}
	}
	return true
}

func findPossibleDecryptedDataAndKeyLength(mapData []byte, mapsData []mapData) ([][]byte, int) {
	valuesByPosition := getValuesByPosition(mapsData)

	keyLength := findFirstPossibleKeyLength(mapData, valuesByPosition)

	decryptedData := initializeDecryptedData(len(mapData), valuesByPosition)

	decryptedData = eliminateImpossibleValuesInDecryptedData(mapData, keyLength, decryptedData, valuesByPosition)
	decryptedData = eliminateValuesWithInvalidKeyInDecryptedData(mapData, decryptedData)
	return decryptedData, keyLength
}

func initializeDecryptedData(dataLength int, valuesByPosition [][]byte) [][]byte {
	decryptedData := make([][]byte, dataLength)
	for i := 0; i < dataLength; i++ {
		decryptedData[i] = make([]byte, len(valuesByPosition[i%CellSize]))
		copy(decryptedData[i], valuesByPosition[i%CellSize])
	}
	return decryptedData
}

func eliminateImpossibleValuesInDecryptedData(mapData []byte, keyLength int, decryptedData [][]byte, valuesByPosition [][]byte) [][]byte {
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

func eliminateValuesWithInvalidKeyInDecryptedData(mapData []byte, decryptedData [][]byte) [][]byte {
	for i := 0; i < len(mapData); i++ {
		newValues := decryptedData[i][:0]
		for _, v := range decryptedData[i] {
			keyValue := mapData[i] ^ v
			if keyValue >= KeyValueMin && keyValue <= KeyValueMax {
				newValues = append(newValues, v)
			}
		}
		decryptedData[i] = newValues
	}
	return decryptedData
}

func decryptedDataToKey(mapData []byte, keyLength int, decryptedData [][]byte) []byte {
	key := make([]byte, keyLength)
	for i := 0; i < len(mapData); i++ {
		if len(decryptedData[i]) == 1 {
			key[i%keyLength] = decryptedData[i][0] ^ mapData[i]
		}
	}
	checksum := checksum(key)
	return escape(rotateRight(key, int(checksum*2)))
}

func rotateRight(data []byte, n int) []byte {
	rotatedData := make([]byte, len(data))
	index := 0
	for i := len(data) - n; i < len(data); i++ {
		rotatedData[index] = data[i]
		index++
	}
	for i := 0; i < len(data)-n; i++ {
		rotatedData[index] = data[i]
		index++
	}
	return rotatedData
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
