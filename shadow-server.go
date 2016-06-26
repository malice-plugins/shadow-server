package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/crackcomm/go-clitable"
	"github.com/levigross/grequests"
	"github.com/parnurzeal/gorequest"
	"github.com/urfave/cli"
	r "gopkg.in/dancannon/gorethink.v2"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

const (
	name     = "shadow-server"
	category = "intel"
)

type pluginResults struct {
	ID   string      `json:"id" gorethink:"id,omitempty"`
	Data ResultsData `json:"shadow-server" gorethink:"shadow-server"`
}

// ShadowServer json object
type ShadowServer struct {
	Results ResultsData `json:"shadow-server"`
}

// ResultsData json object
type ResultsData struct {
	Found     bool             `json:"found"`
	SandBox   SandBoxResults   `json:"sandbox"`
	WhiteList WhiteListResults `json:"whitelist"`
}

// SandBoxResults is a shadow-server SandboxApi results JSON object
type SandBoxResults struct {
	MD5       string            `json:"md5"`
	SHA1      string            `json:"sha1"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
	FileType  string            `json:"type"`
	SSDeep    string            `json:"ssdeep"`
	Antivirus map[string]string `json:"antivirus"`
}

// WhiteListResults is a shadow-server bin-test results JSON object
type WhiteListResults map[string]string

func getopt(name, dfault string) string {
	value := os.Getenv(name)
	if value == "" {
		value = dfault
	}
	return value
}

func assert(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func hashType(hash string) *grequests.RequestOptions {
	if match, _ := regexp.MatchString("([a-fA-F0-9]{32})", hash); match {
		return &grequests.RequestOptions{
			Params: map[string]string{
				"md5": hash,
			},
		}
	} else if match, _ := regexp.MatchString("([a-fA-F0-9]{40})", hash); match {
		return &grequests.RequestOptions{
			Params: map[string]string{
				"sha1": hash,
			},
		}
	} else if match, _ := regexp.MatchString("([a-fA-F0-9]{64})", hash); match {
		return &grequests.RequestOptions{
			Params: map[string]string{
				"sha256": hash,
			},
		}
	} else if match, _ := regexp.MatchString("([a-fA-F0-9]{128})", hash); match {
		return &grequests.RequestOptions{
			Params: map[string]string{
				"sha512": hash,
			},
		}
	} else {
		return &grequests.RequestOptions{ //, fmt.Errorf("%s is not a valid hash", hash)
		}
	}
}

func parseLookupHashOutput(lookupout string, hash string) ResultsData {
	lookup := ResultsData{}

	lines := strings.Split(lookupout, "\n")

	if len(lines) == 2 {
		if strings.Contains(lines[0], "! No match found") {
			lookup.Found = false
			return lookup
		}
		if strings.Contains(lines[0], "! Whitelisted:") {
			lookup.Found = true
			lookup.WhiteList = WhiteListHash(hash)
			return lookup
		}
	} else if len(lines) == 3 {
		values := strings.Split(lines[0], ",")
		lookup.Found = true
		lookup.WhiteList = WhiteListHash(hash)
		if len(values) == 6 {
			lookup.SandBox.MD5 = strings.Trim(values[0], "\"")
			lookup.SandBox.SHA1 = strings.Trim(values[1], "\"")
			// "2009-07-24 02:09:53"
			const longForm = "2006-01-02 15:04:05"
			timeFirstSeen, _ := time.Parse(longForm, strings.Trim(values[2], "\""))
			lookup.SandBox.FirstSeen = timeFirstSeen
			timeLastSeen, _ := time.Parse(longForm, strings.Trim(values[3], "\""))
			lookup.SandBox.LastSeen = timeLastSeen
			lookup.SandBox.FileType = strings.Trim(values[4], "\"")
			lookup.SandBox.SSDeep = strings.Trim(values[5], "\"")
		}
		if len(lines[1]) == 2 {
			lookup.SandBox.Antivirus = nil
		} else {
			assert(json.Unmarshal([]byte(lines[1]), &lookup.SandBox.Antivirus))
		}
	} else {
		log.Fatal(fmt.Errorf("Unable to parse LookupHashOutput: %#v\n", lookupout))
	}

	return lookup
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
	// fmt.Println("whitelist")
	// fmt.Printf("%#v\n", whitelist)
	return whitelist
}

// WhiteListHash test hash against a list of known software applications
func WhiteListHash(hash string) WhiteListResults {

	resp, err := grequests.Get("http://bin-test.shadowserver.org/api", hashType(hash))

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	return parseWhiteListOutput(resp.String())
}

// LookupHash retreieves the shadow-server file report for the given hash
func LookupHash(hash string) ResultsData {
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
	ssResult := parseLookupHashOutput(resp.String(), hash)
	// fmt.Println(resp.String())
	// fmt.Printf("%#v", ssResult)
	return ssResult
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(resp.Status)
}

func printMarkDownTable(ss ShadowServer) {
	fmt.Println("#### ShadowServer")
	if ss.Results.WhiteList != nil {
		fmt.Println("##### WhiteList")
		table := clitable.New([]string{"Found", "Filename", "Description", "ProductName"})
		table.AddRow(map[string]interface{}{
			"Found":       ss.Results.Found,
			"Filename":    ss.Results.WhiteList["filename"],
			"Description": ss.Results.WhiteList["description"],
			"ProductName": ss.Results.WhiteList["product_name"],
		})
		table.Markdown = true
		table.Print()
	} else if ss.Results.SandBox.Antivirus != nil {
		fmt.Println("##### AntiVirus")
		fmt.Printf(" - FirstSeen: %s\n", ss.Results.SandBox.FirstSeen.Format("1/02/2006 3:04PM"))
		fmt.Printf(" - LastSeen: %s\n", ss.Results.SandBox.LastSeen.Format("1/02/2006 3:04PM"))
		fmt.Println()
		table := clitable.New([]string{"Vendor", "Signature"})
		for key, value := range ss.Results.SandBox.Antivirus {
			table.AddRow(map[string]interface{}{"Vendor": key, "Signature": value})
		}
		table.Markdown = true
		table.Print()
	} else {
		fmt.Println(" - Not found")
	}
}

// writeToDatabase upserts plugin results into Database
func writeToDatabase(results pluginResults) {

	address := fmt.Sprintf("%s:28015", getopt("MALICE_RETHINKDB", "rethink"))

	// connect to RethinkDB
	session, err := r.Connect(r.ConnectOpts{
		Address:  address,
		Timeout:  5 * time.Second,
		Database: "malice",
	})
	defer session.Close()

	if err == nil {
		res, err := r.Table("samples").Get(results.ID).Run(session)
		assert(err)
		defer res.Close()

		if res.IsNil() {
			// upsert into RethinkDB
			resp, err := r.Table("samples").Insert(results, r.InsertOpts{Conflict: "replace"}).RunWrite(session)
			assert(err)
			log.Debug(resp)
		} else {
			resp, err := r.Table("samples").Get(results.ID).Update(map[string]interface{}{
				"plugins": map[string]interface{}{
					category: map[string]interface{}{
						name: results.Data,
					},
				},
			}).RunWrite(session)
			assert(err)

			log.Debug(resp)
		}

	} else {
		log.Debug(err)
	}
}

var appHelpTemplate = `Usage: {{.Name}} {{if .Flags}}[OPTIONS] {{end}}COMMAND [arg...]

{{.Usage}}

Version: {{.Version}}{{if or .Author .Email}}

Author:{{if .Author}}
  {{.Author}}{{if .Email}} - <{{.Email}}>{{end}}{{else}}
  {{.Email}}{{end}}{{end}}
{{if .Flags}}
Options:
  {{range .Flags}}{{.}}
  {{end}}{{end}}
Commands:
  {{range .Commands}}{{.Name}}{{with .ShortName}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}
  {{end}}
Run '{{.Name}} COMMAND --help' for more information on a command.
`

func main() {
	cli.AppHelpTemplate = appHelpTemplate
	app := cli.NewApp()
	app.Name = "shadow-server"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice ShadowServer Hash Lookup Plugin"
	var rethinkdb string
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "rethinkdb",
			Value:       "",
			Usage:       "rethinkdb address for Malice to store results",
			EnvVar:      "MALICE_RETHINKDB",
			Destination: &rethinkdb,
		},
		cli.BoolFlag{
			Name:   "post, p",
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
	app.Action = func(c *cli.Context) {
		if c.Args().Present() {
			if c.Bool("verbose") {
				log.SetLevel(log.DebugLevel)
			}
			hash := c.Args().First()
			ssReport := LookupHash(hash)
			ss := ShadowServer{Results: ssReport}

			// upsert into Database
			writeToDatabase(pluginResults{ID: getopt("MALICE_SCANID", hash), Data: ss.Results})

			if c.Bool("table") {
				printMarkDownTable(ss)
			} else {
				ssJSON, err := json.Marshal(ss)
				assert(err)
				fmt.Println(string(ssJSON))
			}
		} else {
			log.Fatal(fmt.Errorf("Please supply a MD5/SHA1 hash to query."))
		}
	}

	err := app.Run(os.Args)
	assert(err)
}
