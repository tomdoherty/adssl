package adssl

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	b64 "encoding/base64"

	"github.com/Azure/go-ntlmssp"
)

// Server represents the AD CA
type Server struct {
	Endpoint, Username, Password string
}

// Request contains all we need to make the Certificate Request
type Request struct {
	CommonName                  string
	Country, Province, Locality string
	DNSNames                    string
	IPAddresses                 string
}

// Certificate contains a x509 certificate
type Certificate struct {
	PrivateKey         *rsa.PrivateKey
	RequestTemplate    x509.CertificateRequest
	PrivateKeyString   string
	CaCert             string
	CertificateRequest string
	Result             string
	ResultURL          string
}

func (c *Certificate) generateTemplate(r Request) error {
	var ipaddrs []net.IP
	for _, ip := range strings.Split(r.IPAddresses, ",") {
		ipaddrs = append(ipaddrs, net.ParseIP(ip))
	}

	c.RequestTemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: r.CommonName,
			Country:    []string{r.Country},
			Province:   []string{r.Province},
			Locality:   []string{r.Locality},
		},
		DNSNames:    strings.Split(r.DNSNames, ","),
		IPAddresses: ipaddrs,
	}
	return nil
}

func (c *Certificate) generatePrivateKey() (err error) {
	var keyBuffer bytes.Buffer

	c.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)

	if err := pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.PrivateKey)}); err != nil {
		return err
	}
	c.PrivateKeyString = keyBuffer.String()
	return err
}

func (c *Certificate) generateCertificateRequest(r Request) (err error) {
	var csr bytes.Buffer
	var csrBytes []byte

	if csrBytes, err = x509.CreateCertificateRequest(rand.Reader, &c.RequestTemplate, c.PrivateKey); err != nil {
		return err
	}

	if err := pem.Encode(&csr, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		return err
	}

	c.CertificateRequest = csr.String()
	return nil
}

func makeAuthenticatedRequest(s Server, path string, body string) (*http.Response, error) {
	var err error
	var req *http.Request
	url := s.Endpoint + path
	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	if body != "" {
		req, err = http.NewRequest("POST", url, strings.NewReader(body))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Content-Length", strconv.Itoa(len(body)))
	} else {
		req, err = http.NewRequest("GET", url, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to request %s: %v", url, err)
	}

	req.SetBasicAuth(s.Username, s.Password)

	resp, err := client.Do(req)
	return resp, err
}

func (c *Certificate) fetchCaCert(s Server) error {
	resp, err := makeAuthenticatedRequest(s, "/certsrv/certcarc.asp", "")

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	dataInBytes, err := ioutil.ReadAll(resp.Body)

	re := regexp.MustCompile("nRenewals=([0-9]+);")

	renewal := "0"
	found := re.FindStringSubmatch(string(dataInBytes))

	if len(found) > 1 {
		renewal = found[1]
	}

	caCertURL := "/certsrv/certnew.cer?ReqID=CACert&Enc=b64&Mode=inst&" + renewal
	resp, err = makeAuthenticatedRequest(s, caCertURL, "")

	if err != nil {
		return fmt.Errorf("Failed to request %s: %v", caCertURL, err)
	}

	defer resp.Body.Close()

	dataInBytes, err = ioutil.ReadAll(resp.Body)
	c.CaCert = string(dataInBytes)

	return nil
}

func (c *Certificate) requestNewCert(s Server) error {
	headers := url.Values{}
	headers.Set("Mode", "newreq")
	headers.Set("CertRequest", c.CertificateRequest)
	headers.Set("CertAttrib", "CertificateTemplate:CUCM-WebServer")
	headers.Set("TargetStoreFlags", "0")
	headers.Set("SaveCert", "yes")

	resp, err := makeAuthenticatedRequest(s, "/certsrv/certfnsh.asp", headers.Encode())

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	dataInBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	re := regexp.MustCompile("certnew.cer\\?ReqID=([0-9]*)&amp;Enc=b64")
	reqID := re.FindString(string(dataInBytes))

	if reqID == "" {
		return fmt.Errorf("Failed to get new cert ReqID")
	}

	c.ResultURL = "/certsrv/" + reqID
	return nil
}

func (c *Certificate) fetchCertResult(s Server) error {
	resp, err := makeAuthenticatedRequest(s, c.ResultURL, "")

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	dataInBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	c.Result = string(dataInBytes)
	return nil
}

// PrintKubeSecret ouputs Certificate in kubernetes YAML
func PrintKubeSecret(w io.Writer, c Certificate) error {
	secret := `apiVersion: v1
kind: Secret
name: tls-secret
data:
  ca.crt: {{.Cacrt}}
  tls.key: {{.Tlskey}}
  tls.crt: {{.Tlscrt}}
`
	t := template.Must(template.New("secret").Parse(secret))
	r := struct {
		Cacrt  string
		Tlskey string
		Tlscrt string
	}{
		b64.StdEncoding.EncodeToString([]byte(c.CaCert)),
		b64.StdEncoding.EncodeToString([]byte(c.PrivateKeyString)),
		b64.StdEncoding.EncodeToString([]byte(c.Result)),
	}
	if err := t.Execute(w, r); err != nil {
		return fmt.Errorf("error templating secret: %v", err)
	}
	return nil
}

// WriteFile writes content to filename
func WriteFile(filename, content string) error {
	fmt.Printf("writing %q\n", filename)
	err := ioutil.WriteFile(filename, []byte(content), 0600)
	return err
}

// New returns a new Request
func New(s Server, r Request) (Certificate, error) {
	var c Certificate
	if err := c.generatePrivateKey(); err != nil {
		log.Fatal(err)
	}
	if err := c.generateTemplate(r); err != nil {
		log.Fatal(err)
	}
	if err := c.generateCertificateRequest(r); err != nil {
		log.Fatal(err)
	}
	if err := c.requestNewCert(s); err != nil {
		log.Fatal(err)
	}
	if err := c.fetchCertResult(s); err != nil {
		log.Fatal(err)
	}
	if err := c.fetchCaCert(s); err != nil {
		log.Fatal(err)
	}

	return c, nil
}
