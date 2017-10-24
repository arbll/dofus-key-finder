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

	createOutputTable := "CREATE TABLE IF NOT EXISTS `output_maps` (" +
		"`id` int(10) NOT NULL," +
		"`date` varchar(32) NOT NULL DEFAULT ''," +
		"`mapData` text," +
		"`key` text," +
		"`decryptedData` text," +
		"`sa` int(11) DEFAULT NULL)"

	addPrimaryKeys := "ALTER TABLE `output_maps` ADD PRIMARY KEY (`id`,`date`)"

	stmt, err := db.Prepare(createOutputTable)
	if err != nil {
		log.Fatal(err)
	}

	stmt.Exec()

	stmt, err = db.Prepare(addPrimaryKeys)
	if err != nil {
		log.Fatal(err)
	}

	stmt.Exec()
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
	if rowExists(db, "SELECT id FROM output_maps WHERE id=? AND date=?", mapData.Id, mapData.Date) {
		stmt, err := db.Prepare("UPDATE output_maps SET `key`=?, decryptedData=? WHERE id=? AND date=?")
		if err != nil {
			log.Fatal(err)
		}
		stmt.Exec(key, ApplyKeyToMap(key, mapData), mapData.Id, mapData.Date)
	} else {
		stmt, err := db.Prepare("INSERT INTO `output_maps` (`id`,date,mapData,`key`,decryptedData,sa) VALUES (?,?,?,?,?,?)")
		if err != nil {
			log.Fatal(err)
		}
		stmt.Exec(mapData.Id, mapData.Date, mapData.data, key, ApplyKeyToMap(key, mapData), mapData.SubArea)
	}
}

func rowExists(db *sql.DB, query string, args ...interface{}) bool {
	var exists bool
	query = fmt.Sprintf("SELECT exists (%s)", query)
	err := db.QueryRow(query, args...).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		log.Fatalf("error checking if row exists '%s' %v", args, err)
	}
	return exists
}
