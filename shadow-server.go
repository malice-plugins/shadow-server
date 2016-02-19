package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/codegangsta/cli"
	"github.com/crackcomm/go-clitable"
	"github.com/levigross/grequests"
	"github.com/parnurzeal/gorequest"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

// ShadowServer json object
type ShadowServer struct {
	Results ResultsData `json:"shadow-server"`
}

// ResultsData json object
type ResultsData struct {
	MD5       string `json:"md5"`
	Sha1      string `json:"sha1"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	FileType  string `json:"type"`
	SSDeep    string `json:"ssdeep"`
	Antivirus AV     `json:"av"`
}

// AV is a shadow-server AV results JSON object
type AV struct {
	Vendor    string
	Signature string
}

// ScanResults json object
type ScanResults struct {
	Permalink    string `json:"permalink"`
	Resource     string `json:"resource"`
	ResponseCode int    `json:"response_code"`
	ScanID       string `json:"scan_id"`
	VerboseMsg   string `json:"verbose_msg"`
	MD5          string `json:"md5"`
	Sha1         string `json:"sha1"`
	Sha256       string `json:"sha256"`
}

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

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(resp.Status)
}

func printMarkDownTable(ss ShadowServer) {
	fmt.Println("#### shadow-server")
	table := clitable.New([]string{"Ratio", "Link", "API", "Scanned"})
	table.AddRow(map[string]interface{}{
		"Ratio": getRatio(ss.Results.Positives, ss.Results.Total),
		"Link":  fmt.Sprintf("[link](%s)", ss.Results.Permalink),
		"API":   "Public",
		// "API":     ss.ApiType,
		"Scanned": time.Now().Format("Mon 2006Jan02 15:04:05"),
	})
	table.Markdown = true
	table.Print()
}

// scanFile uploads file to shadow-server
func scanFile(path string, apikey string) string {
	// fmt.Println("Uploading file to shadow-server...")
	ro := &grequests.RequestOptions{
		Params: map[string]string{
			"resource": scanResults.Sha256,
			"scan_id":  scanResults.ScanID,
			"apikey":   apikey,
			"allinfo":  "1",
		},
	}
	resp, err = grequests.Get("https://www.shadow-server.com/vtapi/v2/file/report", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	// fmt.Println(resp.String())
	return resp.String()
}

// lookupHash retreieves the shadow-server file report for the given hash
func lookupHash(hash string, apikey string) ResultsData {
	// NOTE: https://godoc.org/github.com/levigross/grequests
	// fmt.Println("Getting shadow-server report...")
	ro := &grequests.RequestOptions{
		Params: map[string]string{
			"resource": hash,
			"apikey":   apikey,
			"allinfo":  "1",
		},
	}
	resp, err := grequests.Get("https://www.shadow-server.com/vtapi/v2/file/report", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}
	var vtResult ResultsData
	// fmt.Println(resp.String())
	// return resp.String()
	resp.JSON(&vtResult)
	// fmt.Printf("%#v", vtResult)
	return vtResult
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
	var apikey string
	app.Flags = []cli.Flag{
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
	}
	app.Commands = []cli.Command{
		{
			Name:      "lookup",
			Aliases:   []string{"l"},
			Usage:     "Get file hash sandbox report",
			ArgsUsage: "MD5/SHA1 hash of file",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "table, t",
					Usage: "output as Markdown table",
				},
			},
			Action: func(c *cli.Context) {
				if c.Args().Present() {
					path := c.Args().First()
					// Check that file exists
					if _, err := os.Stat(path); os.IsNotExist(err) {
						assert(err)
					}
					scanFile(path, apikey)
				} else {
					log.Fatal(fmt.Errorf("Please supply a file to upload to shadow-server."))
				}
			},
		},
		{
			Name:      "whitelist",
			Aliases:   []string{"w"},
			Usage:     "test hash against a list of known software applications",
			ArgsUsage: "MD5/SHA1/SHA256/SHA512 hash of file",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "table, t",
					Usage: "output as Markdown table",
				},
			},
			Action: func(c *cli.Context) {
				if c.Args().Present() {
					ssReport := lookupHash(c.Args().First(), apikey)
					ss := ShadowServer{Results: ssReport}
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
			},
		},
	}

	err := app.Run(os.Args)
	assert(err)
}
