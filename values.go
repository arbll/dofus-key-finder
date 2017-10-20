package main

func getValuesProbabilityByPosition(mapsData []mapData) []map[byte]float64 {
	probabilityByPosition := []map[byte]float64{}
	for i := 0; i < CELL_SIZE; i++ {
		probabilityByPosition = append(probabilityByPosition, getValuesProbabilityAtPosition(mapsData, i))
	}
	return probabilityByPosition
}

func getValuesProbabilityAtPosition(mapsData []mapData, position int) map[byte]float64 {
	valueCountMap := make(map[byte]int)
	valueTotalCount := 0
	for _, md := range mapsData {
		data := md.decryptedData
		for i := position; i < len(data); i += CELL_SIZE {
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

func getValuesByPosition(probabilityByPosition []map[byte]float64) [][]byte {
	valuesByPosition := make([][]byte, CELL_SIZE)
	for c, vp := range probabilityByPosition {
		values := make([]byte, len(vp))
		i := 0
		for k := range vp {
			values[i] = k
			i++
		}
		valuesByPosition[c] = values
	}
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

func getXoredValuesProbabilityForPositions(firstPosition int, secondPosition int, probabilityByPosition []map[byte]float64) map[byte]float64 {
	valueProbabilityMap := make(map[byte]float64)
	for v1, p1 := range probabilityByPosition[firstPosition] {
		for v2, p2 := range probabilityByPosition[secondPosition] {
			v := v1 ^ v2
			p := p1 * p2
			if probability, contains := valueProbabilityMap[v]; contains {
				valueProbabilityMap[v] = p + probability
			} else {
				valueProbabilityMap[v] = p
			}
		}
	}
	return valueProbabilityMap
}

func getPossibleValuesAtPositionFromXoredValue(xoredValue byte, values []byte, valuesForXor []byte) []byte {
	possibleValues := []byte{}
	for _, v1 := range values {
		for _, v2 := range valuesForXor {
			v := v1 ^ v2
			if v == xoredValue {
				possibleValues = append(possibleValues, v1)
			}
		}
	}
	return possibleValues
}
