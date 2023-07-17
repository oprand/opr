package main

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/Masterminds/sprig/v3"
	"github.com/muesli/termenv"
	"github.com/oprand/opr/asn"
	"github.com/oprand/opr/client"
	"github.com/urfave/cli/v2"
)

var (
	version = "dev"
	commit  = "********"
)

// parseFlagsAndArgs checks if any args is actually a flag (expect the first, assume it's actual input)
// If that's the case, try to convert it to the corresponding flag or return error.
func parseFlagsAndArgs(c *cli.Context) ([]string, error) {

	var input []string

	// If no arguments given try to read from stdin
	if !c.Args().Present() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			in := strings.TrimSpace(scanner.Text())
			for _, p := range strings.Split(in, " ") {
				in := strings.TrimSpace(p)
				in = strings.TrimLeft(in, ",")
				in = strings.TrimRight(in, ",")
				input = append(input, in)
			}
		}
		if len(input) == 0 {
			return input, fmt.Errorf("no input found")
		}
	}

	for _, arg := range c.Args().Slice() {
		if strings.HasPrefix(arg, "--") {
		flag_loop:
			for i, flag := range c.Command.Flags {
				noHyphenFlag := strings.TrimLeft(arg, "-")
				for _, flagName := range flag.Names() {
					if noHyphenFlag == flagName {
						err := c.Set(noHyphenFlag, "true")
						if err != nil {
							return input, fmt.Errorf("error setting flag: %w", err)
						}
						break flag_loop
					}
					if i+1 == len(c.Command.Flags) {
						return input, fmt.Errorf("%s: flag not recogized", arg)
					}
				}
			}
		} else {
			in := strings.TrimSpace(arg)
			in = strings.TrimLeft(in, ",")
			in = strings.TrimRight(in, ",")
			input = append(input, in)
		}
	}

	return input, nil

}

func run(args []string, stdout io.Writer) error {

	cliapp := cli.NewApp()
	cliapp.Name = "OPRAND CLI tool"
	cliapp.Usage = "CLI tool to access Oprand data"
	cliapp.Version = fmt.Sprintf("%s - Commit: %s", version, strings.ToUpper(commit[:8]))
	cliapp.EnableBashCompletion = true
	cliapp.UsageText = "opr [global flags] <command> [command flags] [example.com | ASN | IP]"
	cliapp.CustomAppHelpTemplate = getAppHelpText()

	resultsCommand := cli.Command{
		Category:  "PRIVATE",
		Name:      "results",
		Aliases:   []string{"r"},
		Usage:     "Fetch all your scan results",
		UsageText: "opr results [command flags] example.com",
		Description: `
    Example to get all suspicious domains with a Web server and a Whois record:
            opr results --query=web,whois example.com

    Same thing but in JSON format:
            opr results --json --query=web,whois example.com

    To download all suspicious domains detected in CSV format:
            opr results --csv example.com

    To see all suspicious domains detected in a human-friendly format:
            opr results example.com
            `,
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:      "query",
				Aliases:   []string{"q"},
				Usage:     client.GetResultQueryUsage(),
				KeepSpace: false,
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output results in JSON format",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "csv",
				Usage: "Output results in CSV format",
				Value: false,
			},
		},
		Action: func(c *cli.Context) error {

			domain := c.Args().First()
			if len(c.Args().Tail()) > 0 && strings.HasPrefix(c.Args().Tail()[0], "-") {
				return fmt.Errorf("options must be right after the command, example: opr results --query=web %s", domain)
			}

			oprClient := client.New(client.OprClientParams{NeedAuth: true})
			return oprClient.FetchResults(c, domain)

		},
	}

	asnCommand := cli.Command{
		Category: "PUBLIC",
		Name:     "asn",
		Aliases:  []string{"a"},
		Usage: `Get Autonomous System information from:
  * Its AS number (ex: AS3)
  * Any of its member IPv4 address (ex: 1.1.1.1)
  * Any domain (ex: oprand.com)
  * The email address' domain used to register the AS (registrant/admin/abuse) (ex: @mit.edu)
  * Or use "me" to get your IP's Autonomous System information`,
		UsageText: "opr asn [command flags] <as-number | ipv4 | @example.com | example.com | \"me\">",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output results in JSON format",
				Value: false,
			},
			&cli.BoolFlag{
				Name:    "ip",
				Aliases: []string{"ips"},
				Usage:   "Output only the assignable IPv4 under the ASN",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:    "cidr",
				Aliases: []string{"netblocks", "netblock"},
				Usage:   "Output only CIDR (IPv4 and IPv6) under the ASN",
				Value:   false,
			},
		},
		Action: func(c *cli.Context) error {

			input, err := parseFlagsAndArgs(c)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n\n", c.Command.UsageText)
				fmt.Fprint(os.Stderr, "Flags available:\n")
				for _, f := range c.Command.Flags {
					fmt.Fprintf(os.Stderr, "%s\n", f)
				}
				fmt.Fprint(os.Stderr, "\n")
				return err
			}

			oprClient := client.New(client.OprClientParams{NeedAuth: false})

			asnResponse, err := oprClient.GetAsn(input...)
			if err != nil {
				return err
			}

			err = asn.CliHandler(asnResponse, c)
			if err != nil {
				return err
			}

			return nil

		},
	}

	domainsCommand := cli.Command{
		Category:  "PRIVATE",
		Name:      "domains",
		Aliases:   []string{"d"},
		Usage:     "List your verified domains, used to generate fuzzed domains",
		UsageText: "opr domains [command flags]",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output results in JSON format",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "csv",
				Usage: "Output results in CSV format",
				Value: false,
			},
		},
		Action: func(c *cli.Context) error {

			oprClient := client.New(client.OprClientParams{NeedAuth: true})
			return oprClient.FetchDomains(c)

		},
	}

	configCommand := cli.Command{
		Category:  "PRIVATE (Oprand account required)",
		Name:      "config",
		Aliases:   []string{"c"},
		Usage:     "Setup your Oprand API authentication credentials",
		UsageText: "opr config",
		Action: func(c *cli.Context) error {

			oprClient := client.New(client.OprClientParams{NeedAuth: false})
			return oprClient.SetupConfig()

		},
	}

	cliapp.Commands = []*cli.Command{
		&resultsCommand,
		&domainsCommand,
		&asnCommand,
		&configCommand,
	}

	cliapp.Suggest = true

	sort.Sort(cli.FlagsByName(cliapp.Flags))
	sort.Sort(cli.CommandsByName(cliapp.Commands))

	// Silent broken pipe errors.
	// 	   SIGPIPE is sent to a proccess when it writes on a pipe with that has no reader.
	// 	   In our case the writting process is our CLI tool writing to stdout.
	//     When piping its output to another programm that will stop reading
	//     after some bytes (for instance `| head`), SIGPIPE will be sent to our CLI tool.
	//	   This is a normal operation and not an error per se.
	//     Here we catch this signal, and thus allow code path like this for writer ops:
	//     errors.Is(err, syscall.EPIPE)
	pipeSigChan := make(chan os.Signal, 1)
	signal.Notify(pipeSigChan, syscall.SIGPIPE)
	go func() {
		<-pipeSigChan
	}()

	return cliapp.Run(os.Args)

}

func main() {

	const exitFail = 1

	if err := run(os.Args, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(exitFail)
	}

}

func getAppHelpText() string {

	line := `
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {{Bold "NAME"}}  opr - OPRAND CLI tool
  {{Bold "AUTHOR"}}  https://oprand.com
──────────────────────────────────────────────────────────────────────
   {{Bold "USAGE"}}  opr [global flags] <command> [command flags] <input>
──────────────────────────────────────────────────────────────────────
 {{Bold "PUBLIC COMMANDS"}}
     asn, a      Get Autonomous System (ASN) information.
                   ‣ By AS number {{Foreground "#AAA" "....."}} opr asn AS3
                   ‣ By IP address {{Foreground "#AAA" "...."}} opr asn 1.1.1.1
                   ‣ By domain {{Foreground "#AAA" "........"}} opr asn example.com
                   ‣ By the registrant 
                     email's domain {{Foreground "#AAA" "..."}} opr asn @orange.com
                   ‣ Your IP's ASN {{Foreground "#AAA" "...."}} opr asn me
     help, h     Shows this list of commands or help for one command
──────────────────────────────────────────────────────────────────────
 {{Bold "PRIVATE COMMANDS"}} - Requires an oprand.com account
     domains, d  List your verified domains.
     results, r  Fetch your verified domains' scan results.
     config, c   Setup your Oprand API authentication credentials.
──────────────────────────────────────────────────────────────────────
 {{Bold "GLOBAL OPTIONS"}}
     --help, -h     show help
     --version, -v  print the version
──────────────────────────────────────────────────────────────────────
 {{Bold "VERSION"}}  {{.Version}} - Commit: {{trunc 8 (upper .CommitHash)}}
 {{Bold "LICENSE"}}  GPL-3.0
──────────────────────────────────────────────────────────────────────
 {{Bold "DISCLAIMER"}}
     We (oprand.com and its authors) assume no liability and are not
     responsible for any misuse or damage caused by this software.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`

	termOutput := termenv.NewOutput(os.Stdout, termenv.WithColorCache(true))
	f := termOutput.TemplateFuncs()
	tmpl, err := template.New("tpl").Funcs(f).Funcs(sprig.FuncMap()).Parse(line)
	if err != nil {
		panic(err)
	}

	var buff bytes.Buffer
	err = tmpl.Execute(&buff,
		struct {
			CommitHash string
			Version    string
		}{
			CommitHash: commit,
			Version:    version,
		},
	)
	if err != nil {
		panic(err)
	}

	return buff.String()

}
