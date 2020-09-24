package files

import (
	"fmt"
	"io/ioutil"
	"log"
)

// OutputFiles writes certs/keys to files
func OutputFiles(cacrt string, tlskey string, tlscrt string) error {
	log.Println("writing ca.crt")
	if err := ioutil.WriteFile("ca.crt", []byte(cacrt), 0600); err != nil {
		return fmt.Errorf("error: %v", err)
	}

	log.Println("writing tls.key")
	if err := ioutil.WriteFile("tls.key", []byte(tlskey), 0600); err != nil {
		return fmt.Errorf("error: %v", err)
	}

	log.Println("writing tls.crt")
	if err := ioutil.WriteFile("tls.crt", []byte(tlscrt), 0600); err != nil {
		return fmt.Errorf("error: %v", err)
	}

	return nil
}
