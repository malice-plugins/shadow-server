package main

const tpl = `#### ShadowServer
{{ with $wl := .WhiteList }}
##### WhiteList
| Filename      | Description      | ProductName      |
|:-------------:|:-------------:|:----------------:|:----------------:|
| {{index $wl "filename"}} | {{index $wl "description"}} | {{index $wl "product_name"}} |
{{ end }}
{{ if .SandBox.Antivirus -}}
##### AntiVirus
 - FirstSeen: {{index .SandBox.MetaData "first_seen"}}
 - LastSeen: {{index .SandBox.MetaData "last_seen"}}
| Vendor          | Signature        |
|:---------------:|:----------------:|
{{- range $key, $value := .SandBox.Antivirus }}
| {{ $key }} | {{ $value }} |
{{- end }}
{{ else }}
 - Not found
{{- end }}
`

// func printMarkDownTable(ss ShadowServer) {
// 	fmt.Println("#### ShadowServer")
// 	if ss.Results.WhiteList != nil {
// 		fmt.Println("##### WhiteList")
// 		table := clitable.New([]string{"Found", "Filename", "Description", "ProductName"})
// 		table.AddRow(map[string]interface{}{
// 			"Found":       ss.Results.Found,
// 			"Filename":    ss.Results.WhiteList["filename"],
// 			"Description": ss.Results.WhiteList["description"],
// 			"ProductName": ss.Results.WhiteList["product_name"],
// 		})
// 		table.Markdown = true
// 		table.Print()
// 	} else if ss.Results.SandBox.Antivirus != nil {
// 		fmt.Println("##### AntiVirus")
// 		// fmt.Printf(" - FirstSeen: %s\n", ss.Results.SandBox.MetaData["first_seen"].Format("1/02/2006 3:04PM"))
// 		fmt.Printf(" - FirstSeen: %s\n", printTableFormattedTime(ss.Results.SandBox.MetaData["first_seen"]))
// 		fmt.Printf(" - LastSeen: %s\n", printTableFormattedTime(ss.Results.SandBox.MetaData["last_seen"]))
// 		fmt.Println()
// 		table := clitable.New([]string{"Vendor", "Signature"})
// 		for key, value := range ss.Results.SandBox.Antivirus {
// 			table.AddRow(map[string]interface{}{"Vendor": key, "Signature": value})
// 		}
// 		table.Markdown = true
// 		table.Print()
// 	} else {
// 		fmt.Println(" - Not found")
// 	}
// 	fmt.Println()
// }
