package dfkey

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

const CellSize int = 10
const KeySizeMin int = 256 / 2
const KeySizeMax int = 554 / 2
const KeyValueMin byte = 32
const KeyValueMax byte = 127

//MapData contains data for a map
type MapData struct {
	Id            int
	data          string
	key           string
	decryptedData string
	Date          string
	SubArea       int
}

//ConnectDB connects to the database containing the maps
func ConnectDB(connectionString string) *sql.DB {
	var db, err = sql.Open("mysql", connectionString)
	if err != nil {
		fmt.Printf("Scan: %v", err)
	}
	return db
}

//GetKnownMapsData returns all the known maps
func GetKnownMapsData(db *sql.DB) []MapData {
	rows, err := db.Query("SELECT id,mapData,`key`,decryptedData,date,sa FROM static_maps")
	if err != nil {
		fmt.Printf("Scan: %v", err)
	}
	var mapsData []MapData
	for rows.Next() {
		var d MapData
		var key sql.NullString
		var decryptedData sql.NullString
		var subArea sql.NullInt64
		err = rows.Scan(&d.Id, &d.data, &key, &decryptedData, &d.Date, &subArea)
		if decryptedData.Valid && key.Valid {
			d.decryptedData = decryptedData.String
			d.key = key.String
		}
		if subArea.Valid {
			d.SubArea = int(subArea.Int64)
		}
		if err != nil {
			fmt.Printf("Scan: %v", err)
		}
		mapsData = append(mapsData, d)
	}
	return mapsData
}

//SaveKey saves a map key
func SaveKey(key string, mapData MapData, db *sql.DB) {
	stmt, err := db.Prepare("UPDATE static_maps SET `key`=?, decryptedData=? WHERE id=? AND date=?")
	if err != nil {
		log.Fatal(err)
	}
	stmt.Exec(key, ApplyKeyToMap(key, mapData), mapData.Id, mapData.Date)
}
