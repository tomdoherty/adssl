package main

import (
	"log"
	"os"

	"github.com/tomdoherty/gobblah/pkg/gobblah"
)

func main() {
	cmd := gobblah.Config{}
	err := cmd.Run(os.Args)

	if err != nil {
		log.Fatal(err)
	}
}
