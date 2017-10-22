package main

import "github.com/omen-/dofus-key-finder/dfkey"

func main() {
	mapsData := dfkey.GetKnownMapsData(dfkey.ConnectDB("root:@/AMPS"))
	dfkey.GuessKey(findMapByID(10001, mapsData), mapsData)
}

func findMapByID(mapID int, mapsData []dfkey.MapData) dfkey.MapData {
	for _, m := range mapsData {
		if m.Id == mapID {
			return m
		}
	}
	panic("Map does not exist")
}
