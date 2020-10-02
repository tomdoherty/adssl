package gobblah

import (
	"log"
	"os/user"

	"github.com/tomdoherty/gobblah/pkg/adssl"
	"github.com/tomdoherty/gobblah/pkg/output/files"
	"github.com/tomdoherty/gobblah/pkg/output/kubernetes"
	"github.com/urfave/cli/v2"
)

// Config holds configuration for command
type Config struct {
	Endpoint string
	Username string
	Password string
	Hosts    string
}

// Result holds the certs/keys generated
type Result struct {
	Cacrt  string
	Tlskey string
	Tlscrt string
}

// Run initiates the action
func (c *Config) Run(args []string) error {
	app := &cli.App{
		Usage: "Generate SSL certificates against Active Directory",

		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "endpoint",
				Aliases:     []string{"e"},
				Usage:       "endpoint to use",
				EnvVars:     []string{"ENDPOINT"},
				Required:    true,
				Destination: &c.Endpoint,
			},
			&cli.StringFlag{
				Name:        "username",
				Aliases:     []string{"u"},
				Value:       usernameAsString(),
				Usage:       "username to authenticate with",
				EnvVars:     []string{"USER"},
				Destination: &c.Username,
			},
			&cli.StringFlag{
				Name:        "password",
				Aliases:     []string{"p"},
				Usage:       "username to authenticate with",
				EnvVars:     []string{"PASSWORD"},
				Required:    true,
				Destination: &c.Password,
			},
			&cli.StringFlag{
				Name:        "hosts",
				Aliases:     []string{"l"},
				Usage:       "comma delimited list of hosts to add to cert",
				EnvVars:     []string{"HOSTS"},
				Required:    true,
				Destination: &c.Hosts,
			},
			&cli.BoolFlag{
				Name:    "k8s-secret",
				Aliases: []string{"k"},
				Usage:   "output as a kubernetes secret",
				Value:   false,
			},
		},
		Action: func(ctx *cli.Context) error {
			var res Result
			var err error
			res.Cacrt, res.Tlskey, res.Tlscrt, err = adssl.CreateCertificates(c.Endpoint, c.Username, c.Password, c.Hosts)
			if err != nil {
				log.Fatal(err)
			}
			if ctx.Bool("k8s-secret") {
				kubernetes.OutputSecret(res.Cacrt, res.Tlskey, res.Tlscrt)
			} else {
				files.OutputFiles(res.Cacrt, res.Tlskey, res.Tlscrt)
			}
			return err
		},
	}

	err := app.Run(args)
	return err
}

func usernameAsString() string {
	username, err := user.Current()
	if err != nil {
		log.Fatal("error looking up current user")
	}
	return username.Username
}
