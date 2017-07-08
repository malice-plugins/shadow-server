package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fatih/structs"
	"github.com/gorilla/mux"
	"github.com/levigross/grequests"
	"github.com/maliceio/go-plugin-utils/database/elasticsearch"
	"github.com/maliceio/go-plugin-utils/utils"
	"github.com/parnurzeal/gorequest"
	"github.com/urfave/cli"
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string

	hash string
)

const (
	name     = "shadow_server"
	category = "intel"
)

// ShadowServer json object
type ShadowServer struct {
	Results ResultsData `json:"shadow_server"`
}

// ResultsData json object
type ResultsData struct {
	Found     bool             `json:"found" structs:"found"`
	SandBox   SandBoxResults   `json:"sandbox" structs:"sandbox"`
	WhiteList WhiteListResults `json:"whitelist" structs:"whitelist"`
	MarkDown  string           `json:"markdown,omitempty" structs:"markdown,omitempty"`
}

// SandBoxResults is a shadow-server SandboxApi results JSON object
type SandBoxResults struct {
	MetaData  map[string]string `json:"metadata,omitempty" structs:"metadata,omitempty"`
	Antivirus map[string]string `json:"antivirus" structs:"antivirus"`
}

type sandBoxMetaData struct {
	MD5       string    `json:"md5" structs:"md5"`
	SHA1      string    `json:"sha1" structs:"sha1"`
	FirstSeen time.Time `json:"first_seen" structs:"first_seen"`
	LastSeen  time.Time `json:"last_seen" structs:"last_seen"`
	FileType  string    `json:"type" structs:"type"`
	SSDeep    string    `json:"ssdeep" structs:"ssdeep"`
}

// WhiteListResults is a shadow-server bin-test results JSON object
type WhiteListResults map[string]string

func assert(err error) {
	if err != nil {
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
			"hash":     hash,
		}).Fatal(err)
	}
}

// IsEmpty checks if ResultsData is empty
func (r ResultsData) IsEmpty() bool {
	return reflect.DeepEqual(r, ResultsData{})
}

func hashType(hash string) *grequests.RequestOptions {
	hashTyp, err := utils.GetHashType(hash)
	if err != nil {
		return &grequests.RequestOptions{}
	}

	return &grequests.RequestOptions{Params: map[string]string{hashTyp: hash}}
}

func parseWhiteListOutput(whitelistout string) WhiteListResults {
	whitelist := WhiteListResults{}

	lines := strings.Split(whitelistout, "\n")

	if len(lines) > 1 {

		fields := strings.SplitN(lines[0], " ", 2)

		if len(fields) == 2 {
			if fields[1] == "" {
				return nil
			}
			assert(json.Unmarshal([]byte(fields[1]), &whitelist))
		}
	}

	// fmt.Printf("%#v\n", whitelist)
	return whitelist
}

// whiteListHash test hash against a list of known software applications
func whiteListHash(hash string) WhiteListResults {

	resp, err := grequests.Get("http://bin-test.shadowserver.org/api", hashType(hash))

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	return parseWhiteListOutput(resp.String())
}

func parseSandboxAPIOutput(sandboxapiout string) SandBoxResults {
	var sandbox SandBoxResults

	lines := strings.Split(sandboxapiout, "\n")

	if len(lines) == 1 {
		if strings.Contains(lines[0], "! No match found") {
			return sandbox
		}
		if strings.Contains(lines[0], "! Whitelisted:") {
			return sandbox
		}
	}

	if len(lines) == 2 {
		values := strings.Split(lines[0], ",")
		if len(values) == 6 {
			// "2009-07-24 02:09:53"
			const longForm = "2006-01-02 15:04:05"
			timeFirstSeen, _ := time.Parse(longForm, strings.Trim(values[2], "\""))
			timeLastSeen, _ := time.Parse(longForm, strings.Trim(values[3], "\""))
			meta := make(map[string]string)
			meta["md5"] = strings.Trim(values[0], "\"")
			meta["sha1"] = strings.Trim(values[1], "\"")
			meta["first_seen"] = timeFirstSeen.String()
			meta["last_seen"] = timeLastSeen.String()
			meta["type"] = strings.Trim(values[4], "\"")
			meta["ssdeep"] = strings.Trim(values[5], "\"")
			sandbox = SandBoxResults{MetaData: meta}
		}
		if len(lines[1]) == 2 {
			sandbox.Antivirus = nil
		} else {
			assert(json.Unmarshal([]byte(lines[1]), &sandbox.Antivirus))
		}
	}

	return sandbox
}

// sandboxAPISearch search hash in AV results
func sandboxAPISearch(hash string) SandBoxResults {

	// NOTE: https://godoc.org/github.com/levigross/grequests
	ro := &grequests.RequestOptions{
		Params: map[string]string{
			"query": hash,
		},
	}
	resp, err := grequests.Get("http://innocuous.shadowserver.org/api/", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	// fmt.Println(resp.String())
	return parseSandboxAPIOutput(resp.String())
}

// LookupHash retreieves the shadow-server file report for the given hash
func LookupHash(hash string) ResultsData {

	lookup := ResultsData{}

	lookup.WhiteList = whiteListHash(hash)
	lookup.SandBox = sandboxAPISearch(hash)

	if lookup.IsEmpty() {
		lookup.Found = false
	} else {
		lookup.Found = true
	}
	// fmt.Printf("%#v", lookup)
	return lookup
}

func printTableFormattedTime(t string) string {
	timeInTableFormat, _ := time.Parse("2006-01-02 15:04:05 -0700 UTC", t)
	return timeInTableFormat.Format("1/02/2006 3:04PM")
}

func generateMarkDownTable(ss ShadowServer) string {
	var tplOut bytes.Buffer

	t := template.Must(template.New("").Parse(tpl))

	err := t.Execute(&tplOut, ss.Results)
	if err != nil {
		log.Println("executing template:", err)
	}

	return tplOut.String()
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(body)
}

func webService() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/lookup/{hash}", webLookUp)
	log.Info("web service listening on port :3993")
	log.Fatal(http.ListenAndServe(":3993", router))
}

func webLookUp(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hash = vars["hash"]

	hashType, _ := utils.GetHashType(hash)

	if strings.EqualFold(hashType, "sha1") || strings.EqualFold(hashType, "md5") {
		ss := ShadowServer{Results: LookupHash(hash)}

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		if ss.Results.Found {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}

		if err := json.NewEncoder(w).Encode(ss); err != nil {
			panic(err)
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "please supply a proper MD5/SHA1 hash to query")
	}
}

func main() {

	var elastic string

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "shadow-server"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice ShadowServer Hash Lookup Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "elasitcsearch",
			Value:       "",
			Usage:       "elasitcsearch address for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH",
			Destination: &elastic,
		},
		cli.BoolFlag{
			Name:   "callback, c",
			Usage:  "POST results to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
	}
	app.ArgsUsage = "MD5/SHA1 hash of file"
	app.Action = func(c *cli.Context) error {

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {

			hash = c.Args().First()
			ss := ShadowServer{Results: LookupHash(hash)}
			ss.Results.MarkDown = generateMarkDownTable(ss)

			// upsert into Database
			elasticsearch.InitElasticSearch(elastic)
			elasticsearch.WritePluginResultsToDatabase(elasticsearch.PluginResults{
				ID:       utils.Getopt("MALICE_SCANID", hash),
				Name:     name,
				Category: category,
				Data:     structs.Map(ss.Results),
			})

			if c.Bool("table") {
				fmt.Println(ss.Results.MarkDown)
			} else {
				ss.Results.MarkDown = ""
				ssJSON, err := json.Marshal(ss)
				assert(err)
				if c.Bool("post") {
					request := gorequest.New()
					if c.Bool("proxy") {
						request = gorequest.New().Proxy(os.Getenv("MALICE_PROXY"))
					}
					request.Post(os.Getenv("MALICE_ENDPOINT")).
						Set("X-Malice-ID", utils.Getopt("MALICE_SCANID", hash)).
						Send(string(ssJSON)).
						End(printStatus)

					return nil
				}
				fmt.Println(string(ssJSON))
			}
		} else {
			log.Fatal(fmt.Errorf("please supply a MD5/SHA1 hash to query"))
		}
		return nil
	}

	err := app.Run(os.Args)
	assert(err)
}
