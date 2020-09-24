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
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Azure/go-ntlmssp"
)

func generateTemplate(hosts []string) x509.CertificateRequest {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hosts[0],
			Country:    []string{"US"},
			Province:   []string{"New Jersey"},
			Locality:   []string{"Weehawken"},
		},
		DNSNames:    hosts,
		IPAddresses: hostsToNetIP(hosts),
	}
	return template
}

func hostsToNetIP(hosts []string) (output []net.IP) {
	checked := map[string]struct{}{}
	for _, host := range hosts {
		ips, err := net.LookupHost(host)
		if err != nil {
			fmt.Println("error looking up", host)
		} else {
			for _, ip := range ips {
				if _, found := checked[ip]; !found {
					checked[ip] = struct{}{}
					output = append(output, net.ParseIP(ip))
				}
			}
		}
	}
	return output
}

func genCsr(template x509.CertificateRequest, keyBytes *rsa.PrivateKey) (bytes.Buffer, error) {
	var csr bytes.Buffer
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)

	if err != nil {
		return csr, fmt.Errorf("failed to create CSR: %v", err)
	}

	if err = pem.Encode(&csr, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		return csr, fmt.Errorf("failed to create CSR: %v", err)
	}
	return csr, nil
}

func getCaCert(endpoint string, username string, password string) (string, error) {
	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
	req, err := http.NewRequest("GET", "https://"+endpoint+"/certsrv/certcarc.asp", nil)

	if err != nil {
		return "", fmt.Errorf("failed to get ca cer: %v", err)
	}

	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)
	defer resp.Body.Close()

	if err != nil {
		return "", fmt.Errorf("fail: %v", err)
	}

	dataInBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", fmt.Errorf("fail: %v", err)
	}

	re := regexp.MustCompile("nRenewals=([0-9]+);")

	renewal := "0"
	found := re.FindStringSubmatch(string(dataInBytes))

	if len(found) > 1 {
		renewal = found[1]
	}

	crtURL := "https://" + endpoint + "/certsrv/certnew.cer?ReqID=CACert&Enc=b64&Mode=inst&" + renewal
	req, err = http.NewRequest("GET", crtURL, nil)

	if err != nil {
		return "", fmt.Errorf("failed to request %s: %v", crtURL, err)
	}

	req.SetBasicAuth(username, password)
	resp, err = client.Do(req)
	defer resp.Body.Close()

	if err != nil {
		return "", fmt.Errorf("failed to request %s: %v", crtURL, err)
	}

	dataInBytes, err = ioutil.ReadAll(resp.Body)
	return string(dataInBytes), err

}

func genCertRequest(csr string, endpoint string, username string, password string) (string, error) {
	var resURL string

	data := url.Values{}
	data.Set("Mode", "newreq")
	data.Set("CertRequest", csr)
	data.Set("CertAttrib", "CertificateTemplate:CUCM-WebServer")
	data.Set("TargetStoreFlags", "0")
	data.Set("SaveCert", "yes")

	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	req, err := http.NewRequest("POST", "https://"+endpoint+"/certsrv/certfnsh.asp", strings.NewReader(data.Encode()))

	if err != nil {
		return "", fmt.Errorf("failed to request cert request: %v", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)

	defer resp.Body.Close()

	if err != nil {
		return "", fmt.Errorf("fail: %v", err)
	}

	dataInBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", fmt.Errorf("fail: %v", err)
	}

	pageContent := string(dataInBytes)

	re := regexp.MustCompile("certnew.cer\\?ReqID=([0-9]*)&amp;Enc=b64")
	reqID := re.FindString(string(pageContent))

	if reqID == "" {
		return "", fmt.Errorf("failed to get new cert ReqID: %v", err)
	} 
	resURL = "https://" + endpoint + "/certsrv/" + reqID
	return resURL, nil
}

func fetchCertResult(resURL string, username string, password string) (string, error) {
	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
	req, err := http.NewRequest("GET", resURL, nil)

	if err != nil {
		return "", fmt.Errorf("failed to fetch resulting cert: %v", err)
	}

	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)

	defer resp.Body.Close()

	if err != nil {
		return "", fmt.Errorf("failed to fetch resulting cert: %v", err)
	}

	dataInBytes, err := ioutil.ReadAll(resp.Body)
	return string(dataInBytes), err
}

// CreateCertificates returns certs/keys as strings
func CreateCertificates(endpoint string, username string, password string, hosts string) (cacrt string, tlskey string, tlscert string, err error) {
	var privateKey bytes.Buffer

	keyBytes, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("failed to generate rsa key")
	}

	if err := pem.Encode(&privateKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyBytes)}); err != nil {
		return "", "", "", fmt.Errorf("failed to encode private key: %v", err)
	}

	caCrt, err := getCaCert(endpoint, username, password)

	if err != nil {
		return "", "", "", fmt.Errorf("failed to fetch cacrt: %v", err)
	}

	template := generateTemplate(strings.Split(hosts, ","))

	csr, err := genCsr(template, keyBytes)

	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate csr: %v", err)
	}

	resURL, err := genCertRequest(csr.String(), endpoint, username, password)

	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate csr: %v", err)
	}

	resCrt, err := fetchCertResult(resURL, username, password)

	if err != nil {
		return "", "", "", fmt.Errorf("failed to fetch result: %v", err)
	}

	return caCrt, privateKey.String(), resCrt, nil
}
