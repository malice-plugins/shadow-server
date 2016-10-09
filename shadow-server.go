package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/crackcomm/go-clitable"
	"github.com/fatih/structs"
	"github.com/levigross/grequests"
	"github.com/maliceio/go-plugin-utils/database/elasticsearch"
	"github.com/maliceio/go-plugin-utils/utils"
	"github.com/parnurzeal/gorequest"
	"github.com/urfave/cli"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

const (
	name     = "shadow-server"
	category = "intel"
)

// ShadowServer json object
type ShadowServer struct {
	Results ResultsData `json:"shadow-server"`
}

// ResultsData json object
type ResultsData struct {
	Found     bool             `json:"found" structs:"found"`
	SandBox   SandBoxResults   `json:"sandbox" structs:"sandbox"`
	WhiteList WhiteListResults `json:"whitelist" structs:"whitelist"`
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
			utils.Assert(json.Unmarshal([]byte(fields[1]), &whitelist))
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
			utils.Assert(json.Unmarshal([]byte(lines[1]), &sandbox.Antivirus))
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

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(resp.Status)
}

func printTableFormattedTime(t string) string {
	timeInTableFormat, _ := time.Parse("2006-01-02 15:04:05 -0700 UTC", t)
	return timeInTableFormat.Format("1/02/2006 3:04PM")
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
		// fmt.Printf(" - FirstSeen: %s\n", ss.Results.SandBox.MetaData["first_seen"].Format("1/02/2006 3:04PM"))
		fmt.Printf(" - FirstSeen: %s\n", printTableFormattedTime(ss.Results.SandBox.MetaData["first_seen"]))
		fmt.Printf(" - LastSeen: %s\n", printTableFormattedTime(ss.Results.SandBox.MetaData["last_seen"]))
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
	fmt.Println()
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
	var elasitcsearch string
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
			Destination: &elasitcsearch,
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
	app.Action = func(c *cli.Context) error {
		if c.Args().Present() {
			if c.Bool("verbose") {
				log.SetLevel(log.DebugLevel)
			}
			hash := c.Args().First()
			ssReport := LookupHash(hash)
			ss := ShadowServer{Results: ssReport}

			// upsert into Database
			elasticsearch.InitElasticSearch()
			elasticsearch.WritePluginResultsToDatabase(elasticsearch.PluginResults{
				ID:       utils.Getopt("MALICE_SCANID", hash),
				Name:     name,
				Category: category,
				Data:     structs.Map(ss.Results),
			})

			if c.Bool("table") {
				printMarkDownTable(ss)
			} else {
				ssJSON, err := json.Marshal(ss)
				utils.Assert(err)
				fmt.Println(string(ssJSON))
			}
		} else {
			log.Fatal(fmt.Errorf("Please supply a MD5/SHA1 hash to query."))
		}
		return nil
	}

	err := app.Run(os.Args)
	utils.Assert(err)
}
