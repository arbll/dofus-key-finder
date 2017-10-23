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
	flag.Parse()
	if *dbPtr == "" || *mapsPtr == "" {
		fmt.Println("Usage :")
		flag.PrintDefaults()
		return
	}

	mapsData := dfkey.GetKnownMapsData(dfkey.ConnectDB(*dbPtr))
	for _, m := range strings.Split(*mapsPtr, ",") {
		mapID, _ := strconv.Atoi(m)
		maps := findMapByID(mapID, mapsData)
		for _, targetMap := range maps {
			key := dfkey.GuessKey(targetMap, mapsData)
			if len(key) > 0 {
				fmt.Printf("Found key for %d_%s:\n%s\n", mapID, targetMap.Date, hex.EncodeToString(key))
			}
		}

	}

}

func printBanner() {
	banner := "  _____         __           _  __          ______ _           _           \n |  __ \\       / _|         | |/ /         |  ____(_)         | |          \n | |  | | ___ | |_ _   _ ___| ' / ___ _   _| |__   _ _ __   __| | ___ _ __ \n | |  | |/ _ \\|  _| | | / __|  < / _ \\ | | |  __| | | '_ \\ / _` |/ _ \\ '__|\n | |__| | (_) | | | |_| \\__ \\ . \\  __/ |_| | |    | | | | | (_| |  __/ |   \n |_____/ \\___/|_|  \\__,_|___/_|\\_\\___|\\__, |_|    |_|_| |_|\\__,_|\\___|_|   \n                                       __/ |https://github.com/Omen-/dofus-key-finder\n                                      |___/                                "
	fmt.Printf("%s\n________________________________________________________________________________\n", banner)
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
