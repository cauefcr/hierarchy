package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
	hook "github.com/robotn/gohook"
)

func main() {
	db, _ := sql.Open("sqlite3", os.Args[1]) // Open the created SQLite File
	defer db.Close()                         // Defer Closing the database
	res, err := db.Query("SELECT rawcode from events")
	if err != nil {
		panic(err)
	}
	tmp := uint16(0)
	for res.Next() {
		res.Scan(&tmp)
		fmt.Printf("\"%s\"", hook.RawcodetoKeychar(tmp))
	}
}
