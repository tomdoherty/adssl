package kubernetes

import (
	b64 "encoding/base64"
	"fmt"
	"os"
	"text/template"
)

const secret = `
apiVersion: v1
kind: Secret
name: tls-secret
data:
  ca.crt: {{.Cacrt}}
  tls.key: {{.Tlskey}}
  tls.crt: {{.Tlscrt}}
`

func OutputSecret(cacrt string, tlskey string, tlscrt string) error {
	t := template.Must(template.New("secret").Parse(secret))
	r := struct {
		Cacrt  string
		Tlskey string
		Tlscrt string
	}{
		b64.StdEncoding.EncodeToString([]byte(cacrt)),
		b64.StdEncoding.EncodeToString([]byte(tlskey)),
		b64.StdEncoding.EncodeToString([]byte(tlscrt)),
	}
	if err := t.Execute(os.Stdout, r); err != nil {
		return fmt.Errorf("error templating secret: %v", err)
	}
	return nil
}
