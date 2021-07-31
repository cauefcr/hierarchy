package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	mr "math/rand"
	"net/http"
	"os"
	"time"

	"github.com/cretz/bine/tor"
	// libtor "github.com/ipsn/go-libtor"
	// "github.com/cretz/bine/process/embedded"
	"github.com/clementauger/tor-prebuilt/embedded"
)

const (
	admin    = "root"
	password = "toor"
)

// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func randStr(n int) string {
	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax letters!
	for i, cache, remain := n-1, mr.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = mr.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 1024)
	return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	priv := &rsa.PrivateKey{}
	pub := &rsa.PublicKey{}
	if _, err := os.Stat("private_server.key"); os.IsNotExist(err) {
		priv, pub = GenerateRsaKeyPair()
		// Export the keys to pem string
		priv_pem := ExportRsaPrivateKeyAsPemStr(priv)
		pub_pem, _ := ExportRsaPublicKeyAsPemStr(pub)

		// Import the keys from pem string
		priv_parsed, _ := ParseRsaPrivateKeyFromPemStr(priv_pem)
		pub_parsed, _ := ParseRsaPublicKeyFromPemStr(pub_pem)

		// Export the newly imported keys
		priv_parsed_pem := ExportRsaPrivateKeyAsPemStr(priv_parsed)
		pub_parsed_pem, _ := ExportRsaPublicKeyAsPemStr(pub_parsed)

		fmt.Println(priv_parsed_pem)
		fmt.Println(pub_parsed_pem)

		// Check that the exported/imported keys match the original keys
		if priv_pem != priv_parsed_pem || pub_pem != pub_parsed_pem {
			fmt.Println("Failure: Export and Import did not result in same Keys")
		} else {
			fmt.Println("Success")
		}
		err := ioutil.WriteFile("private_server.key", []byte(priv_pem), 0644)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile("public_server.key", []byte(pub_pem), 0644)
		if err != nil {
			panic(err)
		}

	} else {
		priv_pem, err := ioutil.ReadFile("private_server.key")
		if err != nil {
			panic(err)
		}
		pub_pem, err := ioutil.ReadFile("public_server.key")
		if err != nil {
			panic(err)
		}

		priv, _ = ParseRsaPrivateKeyFromPemStr(string(priv_pem))
		pub, _ = ParseRsaPublicKeyFromPemStr(string(pub_pem))
	}

	// Start tor with default config (can set start conf's DebugWriter to os.Stdout for debug logs)
	fmt.Println("Starting and registering onion service, please wait a couple of minutes...")
	t, err := tor.Start(nil, &tor.StartConf{ProcessCreator: embedded.NewCreator()})
	if err != nil {
		return err
	}
	defer t.Close()
	// Add a handler
	// lg := []string{}
	addrs := map[string]string{}
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	http.HandleFunc("/cc", func(w http.ResponseWriter, r *http.Request) {
		bd, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		addr := struct {
			Self string `json:"self"`
		}{}
		json.Unmarshal(bd, &addr)
		addrs[addr.Self] = addr.Self
		fmt.Println(string(bd))
		w.Write([]byte("Hello Dark World!"))
	})
	sess := map[string]bool{}
	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		// bd, err := ioutil.ReadAll(r.Body)
		// if err != nil {
		// 	panic(err)
		// }
		if r.Method == http.MethodGet {
			t := template.Must(template.ParseFiles("templ/login.tmpl.html"))
			data := struct {
				Title string
			}{Title: "Igraen"}
			t.Execute(w, data)
		} else if r.Method == http.MethodPost {
			err := r.ParseForm()
			if err != nil {
				log.Println(err)
			}
			if r.FormValue("usr") == admin && r.FormValue("password") == password {
				// generate jwt
				token := randStr(128)
				// append jwt to address
				sess[token] = true
				http.Redirect(w, r, fmt.Sprintf("/home?token=%v", token), http.StatusSeeOther)
			}
		}
	})
	http.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		// bd, err := ioutil.ReadAll(r.Body)
		// if err != nil {
		// 	panic(err)
		// }
		query := r.URL.Query()
		if sess[query.Get("token")] == true {
			if r.Method == http.MethodGet {
				t := template.Must(template.ParseFiles("templ/home.tmpl.html"))
				data := struct {
					Log   map[string]string
					Title string
				}{Log: addrs, Title: "Igraen"}
				t.Execute(w, data)
			} else if r.Method == http.MethodPost {
				err := r.ParseForm()
				if err != nil {
					log.Println(err)
				}
			}
		}
	})
	// Wait at most a few minutes to publish the service
	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer listenCancel()
	// Create an onion service to listen on 8080 but show as 80
	port := mr.Int31()
	onion, err := t.Listen(listenCtx, &tor.ListenConf{Version3: true, LocalPort: int(port)%(1<<10) + 1000, Key: priv, RemotePorts: []int{80}})
	if err != nil {
		return err
	}
	defer onion.Close()

	// Serve on HTTP
	fmt.Printf("Open Tor browser and navigate to http://%v.onion\n", onion.ID)
	return http.Serve(onion, nil)
}

func PostToURL(url string, t *tor.Tor, data []byte) (string, error) {
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer dialCancel()
	// Make connection
	dialer, err := t.Dialer(dialCtx, nil)
	if err != nil {
		return "", err
	}
	httpClient := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}
	values := map[string]string{"self": string(data)}

	jsonValue, _ := json.Marshal(values)

	resp, err := httpClient.Post(url, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// fmt.Println("response Status:", resp.Status)
	// fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	// fmt.Println("response Body:", string(body))
	return string(body), nil
}
