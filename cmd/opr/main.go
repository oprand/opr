package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/oprand/opr/cli"

	urfavcli "github.com/urfave/cli/v2"
)

var GitCommitHash string

func run(args []string, stdout io.Writer) error {

	cliapp := urfavcli.NewApp()
	cliapp.Name = "OPRAND CLI"
	cliapp.Usage = "CLI tool to access your Oprand Threat Data"
	cliapp.Version = fmt.Sprintf("v0.0.1 - Commit:%s", GitCommitHash)
	cliapp.EnableBashCompletion = true
	cliapp.UsageText = "opr <command> [command flags] example.com"

	oprClient := cli.OprClient{
		Scheme:     "https",
		BaseUrl:    "api.oprand.com",
		UserAgent:  fmt.Sprintf("Oprand CLI Tool (%s)", cliapp.Version),
		HttpClient: http.DefaultClient,
	}

	resultsCommand := urfavcli.Command{
		Name:      "results",
		Aliases:   []string{"r"},
		Usage:     "Fetch all scan results",
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
		Flags: []urfavcli.Flag{
			&urfavcli.StringSliceFlag{
				Name:      "query",
				Aliases:   []string{"q"},
				Usage:     cli.GetResultQueryUsage(),
				KeepSpace: false,
			},
			&urfavcli.BoolFlag{
				Name:  "json",
				Usage: "Output results in JSON format",
				Value: false,
			},
			&urfavcli.BoolFlag{
				Name:  "csv",
				Usage: "Output results in CSV format",
				Value: false,
			},
		},
		Action: func(c *urfavcli.Context) error {

			domain := c.Args().First()
			return oprClient.FetchResults(c, domain)

		},
	}

	domainsCommand := urfavcli.Command{
		Name:      "domains",
		Aliases:   []string{"d"},
		Usage:     "List verified domains, used to generate fuzzed domains",
		UsageText: "opr domains [command flags]",
		Flags: []urfavcli.Flag{
			&urfavcli.BoolFlag{
				Name:  "json",
				Usage: "Output results in JSON format",
				Value: false,
			},
			&urfavcli.BoolFlag{
				Name:  "csv",
				Usage: "Output results in CSV format",
				Value: false,
			},
		},
		Action: func(c *urfavcli.Context) error {

			return oprClient.FetchDomains(c)

		},
	}

	configCommand := urfavcli.Command{
		Name:      "config",
		Aliases:   []string{"c"},
		Usage:     "Setup your API authentication tokens",
		UsageText: "opr config",
		Action: func(c *urfavcli.Context) error {

			return oprClient.SetupConfig()

		},
	}

	cliapp.Commands = []*urfavcli.Command{
		&resultsCommand,
		&domainsCommand,
		&configCommand,
	}

	sort.Sort(urfavcli.FlagsByName(cliapp.Flags))
	sort.Sort(urfavcli.CommandsByName(cliapp.Commands))

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

	err := cliapp.Run(os.Args)

	return err

}

func main() {

	const exitFail = 1

	if err := run(os.Args, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(exitFail)
	}

}
