package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/codegangsta/cli"
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
	MD5       string            `json:"md5"`
	SHA1      string            `json:"sha1"`
	FirstSeen string            `json:"first_seen"`
	LastSeen  string            `json:"last_seen"`
	FileType  string            `json:"type"`
	SSDeep    string            `json:"ssdeep"`
	Antivirus map[string]string `json:"antivirus"`
}

// AV is a shadow-server AV results JSON object
type AV struct {
	Vendor    string
	Signature string
}

// WhiteListResults json object
type WhiteListResults struct {
	WhiteList map[string]map[string]string `json:"whitelist"`
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
	// table := clitable.New([]string{"Ratio", "Link", "API", "Scanned"})
	// table.AddRow(map[string]interface{}{
	// 	"Ratio": getRatio(ss.Results.Positives, ss.Results.Total),
	// 	"Link":  fmt.Sprintf("[link](%s)", ss.Results.Permalink),
	// 	"API":   "Public",
	// 	// "API":     ss.ApiType,
	// 	"Scanned": time.Now().Format("Mon 2006Jan02 15:04:05"),
	// })
	// table.Markdown = true
	// table.Print()
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

func parseLookUpHashOutput(lookupout string) ResultsData {
	lookup := ResultsData{}

	lines := strings.Split(lookupout, "\n")

	if len(lines) > 2 {
		values := strings.Split(lines[0], ",")

		if len(values) == 6 {
			lookup.MD5 = strings.Trim(values[0], "\"")
			lookup.SHA1 = strings.Trim(values[1], "\"")
			lookup.FirstSeen = strings.Trim(values[2], "\"")
			lookup.LastSeen = strings.Trim(values[3], "\"")
			lookup.FileType = strings.Trim(values[4], "\"")
			lookup.SSDeep = strings.Trim(values[5], "\"")
		}
		assert(json.Unmarshal([]byte(lines[1]), &lookup.Antivirus))
	}

	return lookup
}

func parseWhiteListOutput(whitelistout string) map[string]string {
	var whitelist map[string]string

	lines := strings.Split(whitelistout, "\n")
	// fmt.Println("LINES")
	// fmt.Println("len(lines): ", len(lines))
	// fmt.Printf("%#v\n", lines)
	if len(lines) > 1 {
		// fields := strings.Fields(lines[0])
		fields := strings.SplitN(lines[0], " ", 2)
		// fmt.Println("FIELDS")
		// fmt.Println("len(fields): ", len(fields))
		// fmt.Printf("%#v\n", fields)
		if len(fields) == 2 {
			// 		lookup.MD5 = strings.Trim(values[0], "\"")
			// 		lookup.SHA1 = strings.Trim(values[1], "\"")
			// 		lookup.FirstSeen = strings.Trim(values[2], "\"")
			// 		lookup.LastSeen = strings.Trim(values[3], "\"")
			// 		lookup.FileType = strings.Trim(values[4], "\"")
			// 		lookup.SSDeep = strings.Trim(values[5], "\"")
			// 	}
			assert(json.Unmarshal([]byte(fields[1]), &whitelist))
		}
	}
	// fmt.Println("whitelist")
	// fmt.Printf("%#v\n", whitelist)
	ssJSON, err := json.Marshal(whitelist)
	assert(err)
	fmt.Println(string(ssJSON))
	return whitelist
}

// WhiteListHash test hash against a list of known software applications
func WhiteListHash(hash string) WhiteListResults {
	// fmt.Println("Uploading file to shadow-server...")
	resp, err := grequests.Get("http://bin-test.shadowserver.org/api", hashType(hash))

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	var ssWhiteList WhiteListResults
	// fmt.Println(resp.String())
	// return resp.String()
	// resp.JSON(&ssResult)
	// fmt.Printf("%#v", ssResult)

	_ = parseWhiteListOutput(resp.String())

	return ssWhiteList
}

// lookupHash retreieves the shadow-server file report for the given hash
func lookupHash(hash string) ResultsData {
	// NOTE: https://godoc.org/github.com/levigross/grequests
	// fmt.Println("Getting shadow-server report...")
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
	ssResult := parseLookUpHashOutput(resp.String())
	// var ssResult ResultsData
	// fmt.Println(resp.String())
	// return resp.String()
	// resp.JSON(&ssResult)
	// fmt.Printf("%#v", ssResult)
	return ssResult
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
			ArgsUsage: "MD5/SHA1/SHA256/SHA512 hash of file",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "table, t",
					Usage: "output as Markdown table",
				},
			},
			Action: func(c *cli.Context) {
				if c.Args().Present() {
					ssReport := lookupHash(c.Args().First())
					ss := ShadowServer{Results: ssReport}
					if c.Bool("table") {
						printMarkDownTable(ss)
					} else {
						ssJSON, err := json.Marshal(ss)
						assert(err)
						fmt.Println(string(ssJSON))
					}
				} else {
					log.Fatal(fmt.Errorf("Please supply a MD5/SHA1/SHA256/SHA512 hash to query."))
				}
			},
		},
		{
			Name:      "whitelist",
			Aliases:   []string{"w"},
			Usage:     "Test hash against a list of known software applications",
			ArgsUsage: "MD5/SHA1 hash of file",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "table, t",
					Usage: "output as Markdown table",
				},
			},
			Action: func(c *cli.Context) {
				if c.Args().Present() {
					ssReport := WhiteListHash(c.Args().First())
					// ss := ShadowServer{Results: ssReport}
					if c.Bool("table") {
						// printMarkDownTable(ss)
					} else {
						ssJSON, err := json.Marshal(ssReport)
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
