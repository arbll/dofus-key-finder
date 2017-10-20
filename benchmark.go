package main

import "fmt"

func worker(probabilityByPosition []map[byte]float64, jobs <-chan mapData, results chan<- []int) {
	for j := range jobs {
		result := findPossibleKeyLengths(j, probabilityByPosition)
		results <- result
	}
}

func benchmarkLength(mapsData []mapData, probabilityByPosition []map[byte]float64) {
	mapCount := len(mapsData)
	results := make(chan []int, mapCount)
	jobs := make(chan mapData, mapCount)
	

	for w := 0; w < 8; w++ {
		go worker(probabilityByPosition, jobs, results)
	}

  for _, mapData := range mapsData {
		jobs <- mapData
	}
	
	close(jobs)
	
	okLengths, badLengths, noLengths := 0, 0, 0

	for i := 0;i < 10;i++ {
		lengths := <-results
		switch len(lengths) {
		case 0:
			noLengths++
		case 1:
			okLengths++
		default:
			fmt.Printf("%v\n", lengths)
			badLengths++
		}
	}

	fmt.Printf("Results : %d ok (%f%%), %d not found (%f%%), %d multiple found (%f%%)", okLengths, float32(okLengths) / float32(mapCount) * 100, noLengths, float32(noLengths) / float32(mapCount) * 100, badLengths, float32(badLengths) / float32(mapCount) * 100)
}