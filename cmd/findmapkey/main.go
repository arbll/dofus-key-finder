package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/omen-/dofus-key-finder/dfkey"
)

func main() {
	printBanner()
	dbPtr := flag.String("db", "", "DB connection string. ex: -db=\"user:password@/dbname\" (Required)")
	mapsPtr := flag.String("maps", "", "MapIDs to be decrypted. ex: -maps=1000,1001 (Required)")
	subAreaPtr := flag.String("subareas", "", "SubAreas to be used for data source. Use this only if you understand what you are doing. ex: -subareas=275,276 (Optional)")
	savePtr := flag.Bool("s", false, "Save to the database.")

	flag.Parse()
	if *dbPtr == "" || *mapsPtr == "" {
		fmt.Println("Usage :")
		flag.PrintDefaults()
		return
	}
	db := dfkey.ConnectDB(*dbPtr)
	mapsData := dfkey.GetKnownMapsData(db)

	if *subAreaPtr != "" {
		subAreas := []int{}
		for _, m := range strings.Split(*subAreaPtr, ",") {
			subAreaID, _ := strconv.Atoi(m)
			subAreas = append(subAreas, subAreaID)
		}
		mapsData = filterMapsDataBySubAreas(mapsData, subAreas)
	}

	for _, m := range strings.Split(*mapsPtr, ",") {
		mapID, _ := strconv.Atoi(m)
		maps := findMapByID(mapID, mapsData)
		for _, targetMap := range maps {
			key := hex.EncodeToString(dfkey.GuessKey(targetMap, mapsData))
			if len(key) > 0 {
				if *savePtr {
					dfkey.SaveKey(key, targetMap, db)
					fmt.Printf("Found key for %d_%s has been saved in the database\n", mapID, targetMap.Date)
				} else {
					fmt.Printf("Found key for %d_%s:\n%s\n%s\n", mapID, targetMap.Date, key, dfkey.ApplyKeyToMap(key, targetMap))
				}
			}
		}

	}

}

func printBanner() {
	banner := "  _____         __           _  __          ______ _           _           \n |  __ \\       / _|         | |/ /         |  ____(_)         | |          \n | |  | | ___ | |_ _   _ ___| ' / ___ _   _| |__   _ _ __   __| | ___ _ __ \n | |  | |/ _ \\|  _| | | / __|  < / _ \\ | | |  __| | | '_ \\ / _` |/ _ \\ '__|\n | |__| | (_) | | | |_| \\__ \\ . \\  __/ |_| | |    | | | | | (_| |  __/ |   \n |_____/ \\___/|_|  \\__,_|___/_|\\_\\___|\\__, |_|    |_|_| |_|\\__,_|\\___|_|   \n                                       __/ |https://github.com/Omen-/dofus-key-finder\n                                      |___/                                "
	fmt.Printf("%s\n________________________________________________________________________________\n", banner)
}

func filterMapsDataBySubAreas(mapsData []dfkey.MapData, subAreas []int) []dfkey.MapData {
	filteredMapsData := []dfkey.MapData{}
	for _, m := range mapsData {
		for _, sa := range subAreas {
			if m.SubArea == sa {
				filteredMapsData = append(filteredMapsData, m)
			}
		}
	}
	return filteredMapsData
}

func findMapByID(mapID int, mapsData []dfkey.MapData) []dfkey.MapData {
	maps := []dfkey.MapData{}
	for _, m := range mapsData {
		if m.Id == mapID {
			maps = append(maps, m)
		}
	}
	return maps
}
