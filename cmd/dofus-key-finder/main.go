package main

import (
	"flag"
	"fmt"
	"log"

	"github.int.exe.xyz/arbll/dofus-key-finder/internal/maps"
)

func main() {
	path := flag.String("maps-file", "data/maps.csv", "path to the maps CSV file")
	flag.Parse()

	loaded, err := maps.Load(*path)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Loaded %d maps\n", len(loaded))
}
