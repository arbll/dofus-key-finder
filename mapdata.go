package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "fmt"

const CELL_SIZE int = 10
const KEY_SIZE_MIN int = 256 / 2
const KEY_SIZE_MAX int = 554 / 2

type mapData struct {
	id int
	data string
	key string
	decryptedData string
}

func connect() *sql.DB {
	var db, err = sql.Open("mysql", "root:@/AMPS")
	if err != nil {
		fmt.Printf("Scan: %v", err)
	}
	return db
}

func getKnownMapsData(db *sql.DB) []mapData {
	rows, err := db.Query("SELECT id,mapData,`key`,decryptedData FROM static_maps WHERE `key` IS NOT NULL")
	if err != nil {
		fmt.Printf("Scan: %v", err)
	}
	var mapsData []mapData
	for rows.Next() {
		var d mapData
		err = rows.Scan(&d.id, &d.data, &d.key, &d.decryptedData)
		if err != nil {
			fmt.Printf("Scan: %v", err)
		}
		mapsData = append(mapsData, d)
	}
	return mapsData
}