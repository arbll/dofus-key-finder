package dfkey

import "sync"

var mutexProbability = &sync.Mutex{}
var valuesProbabilityByPosition []map[byte]float64
var mutexValues = &sync.Mutex{}
var valuesByPosition [][]byte

func getValuesProbabilityByPosition(mapsData []MapData) []map[byte]float64 {
	mutexProbability.Lock()
	if valuesProbabilityByPosition != nil {
		mutexProbability.Unlock()
		return valuesProbabilityByPosition
	}
	probabilityByPosition := []map[byte]float64{}
	for i := 0; i < CellSize; i++ {
		probabilityByPosition = append(probabilityByPosition, getValuesProbabilityAtPosition(mapsData, i))
	}
	valuesProbabilityByPosition = probabilityByPosition
	mutexProbability.Unlock()
	return valuesProbabilityByPosition
}

func getValuesProbabilityAtPosition(mapsData []MapData, position int) map[byte]float64 {
	valueCountMap := make(map[byte]int)
	valueTotalCount := 0
	for _, md := range mapsData {
		data := md.decryptedData
		for i := position; i < len(data); i += CellSize {
			valueTotalCount++
			if count, contains := valueCountMap[data[i]]; contains {
				valueCountMap[data[i]] = count + 1
			} else {
				valueCountMap[data[i]] = 1
			}
		}
	}
	valueProbabilityMap := make(map[byte]float64)
	for v, c := range valueCountMap {
		valueProbabilityMap[v] = float64(c) / float64(valueTotalCount)
	}
	return valueProbabilityMap
}

func getValuesByPosition(mapsData []MapData) [][]byte {
	mutexValues.Lock()
	if valuesByPosition != nil {
		mutexValues.Unlock()
		return valuesByPosition
	}
	probabilityByPosition := getValuesProbabilityByPosition(mapsData)
	valuesByPosition = make([][]byte, CellSize)
	for c, vp := range probabilityByPosition {
		values := make([]byte, len(vp))
		i := 0
		for k := range vp {
			values[i] = k
			i++
		}
		valuesByPosition[c] = values
	}
	mutexValues.Unlock()
	return valuesByPosition
}

func getValueProbabilityAtPosition(value byte, position int, probabilityByPosition []map[byte]float64) float64 {
	return getValueProbability(value, probabilityByPosition[position])
}

func getValueProbability(value byte, probability map[byte]float64) float64 {
	if probability, contains := probability[value]; contains {
		return probability
	}
	return 0
}

func getXoredValuesForPositions(firstPosition int, secondPosition int, valuesByPosition [][]byte) []byte {
	valuesMap := []byte{}
	for _, v1 := range valuesByPosition[firstPosition] {
		for _, v2 := range valuesByPosition[secondPosition] {
			v := v1 ^ v2
			valuesMap = appendValueIfMissing(valuesMap, v)
		}
	}
	return valuesMap
}

func getPossibleValuesAtPositionFromXoredValue(xoredValue byte, values []byte, valuesForXor []byte) []byte {
	possibleValues := []byte{}
	for _, v1 := range values {
		for _, v2 := range valuesForXor {
			v := v1 ^ v2
			if v == xoredValue {
				possibleValues = appendValueIfMissing(possibleValues, v1)
			}
		}
	}
	return possibleValues
}

func appendValueIfMissing(values []byte, value byte) []byte {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}

func containsValue(values []byte, value byte) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func removeValue(values []byte, valueIndex int) []byte {
	//fmt.Println(values, valueIndex)
	return append(values[:valueIndex], values[valueIndex+1:]...)
}
