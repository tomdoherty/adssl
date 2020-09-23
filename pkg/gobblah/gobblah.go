package gobblah

import (
	"log"
	"os/user"

	"github.com/tomdoherty/gobblah/pkg/adssl"
	"github.com/urfave/cli/v2"
)

// Config holds configuration for command
type Config struct {
	Endpoint string
	Username string
	Password string
	Hosts    string
}

// Run initiates the action
func (c *Config) Run(args []string) error {
	app := &cli.App{
		Usage: "Generate SSL certificates against Active Directory",

		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "endpoint",
				Aliases:     []string{"e"},
				Value:       "foo.bar.com",
				Usage:       "endpoint to use",
				EnvVars:     []string{"ENDPOINT"},
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
				Value:       "password",
				Usage:       "username to authenticate with",
				EnvVars:     []string{"PASSWORD"},
				Destination: &c.Password,
			},
			&cli.StringFlag{
				Name:        "hosts",
				Aliases:     []string{"l"},
				Value:       "foo1,foo2,foo3",
				Usage:       "comma delimited list of hosts to add to cert",
				EnvVars:     []string{"HOSTSLIST"},
				Destination: &c.Hosts,
			},
		},
		Action: func(cli *cli.Context) error {
			adssl.CreateCertificates(c.Endpoint, c.Username, c.Password, c.Hosts)
			return nil
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
