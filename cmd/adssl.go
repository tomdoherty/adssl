package main

import (
	"fmt"
	"os"

	"github.com/tomdoherty/adssl"
	"github.com/urfave/cli/v2"
)

func main() {
	s := adssl.Server{}
	r := adssl.Request{}

	app := &cli.App{
		Usage: "Generate SSL certificates against Active Directory",

		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "endpoint",
				Aliases:     []string{"e"},
				Usage:       "endpoint url to use",
				EnvVars:     []string{"ENDPOINT"},
				Destination: &s.Endpoint,
			},
			&cli.StringFlag{
				Name:        "username",
				Aliases:     []string{"u"},
				Usage:       "username to authenticate with",
				EnvVars:     []string{"USER"},
				Destination: &s.Username,
			},
			&cli.StringFlag{
				Name:        "password",
				Aliases:     []string{"p"},
				Usage:       "username to authenticate with",
				EnvVars:     []string{"PASSWORD"},
				Destination: &s.Password,
			},
			&cli.StringFlag{
				Name:        "country",
				Aliases:     []string{"C"},
				Usage:       "cert country",
				EnvVars:     []string{"COUNTRY"},
				Required:    true,
				Destination: &r.Country,
			},
			&cli.StringFlag{
				Name:        "province",
				Aliases:     []string{"P"},
				Usage:       "cert province",
				EnvVars:     []string{"PROVINCE"},
				Required:    true,
				Destination: &r.Province,
			},
			&cli.StringFlag{
				Name:        "locality",
				Aliases:     []string{"L"},
				Usage:       "cert locality",
				EnvVars:     []string{"LOCALITY"},
				Required:    true,
				Destination: &r.Locality,
			},
			&cli.StringFlag{
				Name:        "commonname",
				Aliases:     []string{"c"},
				Usage:       "common name",
				EnvVars:     []string{"COMMON"},
				Required:    true,
				Destination: &r.CommonName,
			},
			&cli.StringFlag{
				Name:        "hosts",
				Aliases:     []string{"l"},
				Usage:       "comma delimited list of hosts to add to cert",
				EnvVars:     []string{"HOSTS"},
				Destination: &r.DNSNames,
			},
			&cli.StringFlag{
				Name:        "ips",
				Aliases:     []string{"i"},
				Usage:       "comma delimited list of IPAddresses to add to cert",
				EnvVars:     []string{"IPADDRS"},
				Destination: &r.IPAddresses,
			},
			&cli.StringFlag{
				Name:        "prefix",
				Aliases:     []string{"f"},
				Usage:       "prefix output files",
				EnvVars:     []string{"PREFIX"},
				Destination: &r.Prefix,
			},
			&cli.BoolFlag{
				Name:        "csronly",
				Aliases:     []string{"O"},
				Usage:       "write csr/key only",
				Value:       false,
				Destination: &r.CsrOnly,
			},
			&cli.BoolFlag{
				Name:    "k8s-secret",
				Aliases: []string{"k"},
				Usage:   "output as a kubernetes secret",
				Value:   false,
			},
		},
		Action: func(ctx *cli.Context) error {
			res, err := adssl.New(s, r)
			if err != nil {
				fmt.Printf("fatal: %v\n", err)
				os.Exit(1)
			}
			if ctx.Bool("k8s-secret") {
				adssl.PrintKubeSecret(os.Stdout, res)
			} else {
				if !r.CsrOnly {
					adssl.WriteFile(r.Prefix+"ca.crt", res.CaCert)
					adssl.WriteFile(r.Prefix+"tls.key", res.PrivateKeyString)
					adssl.WriteFile(r.Prefix+"tls.crt", res.Result)
				}
			}

			return err
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
