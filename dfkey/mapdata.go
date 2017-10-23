package dfkey

import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "fmt"

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
	rows, err := db.Query("SELECT id,mapData,`key`,decryptedData,date FROM static_maps")
	if err != nil {
		fmt.Printf("Scan: %v", err)
	}
	var mapsData []MapData
	for rows.Next() {
		var d MapData
		var key sql.NullString
		var decryptedData sql.NullString
		err = rows.Scan(&d.Id, &d.data, &key, &decryptedData, &d.Date)
		if decryptedData.Valid && key.Valid {
			d.decryptedData = decryptedData.String
			d.key = key.String
		}
		if err != nil {
			fmt.Printf("Scan: %v", err)
		}
		mapsData = append(mapsData, d)
	}
	return mapsData
}
