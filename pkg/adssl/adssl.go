package adssl

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"

	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"

	"net"
	"net/http"
	"net/url"

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
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	var csr bytes.Buffer
	pem.Encode(&csr, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csr, err
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
		panic(err)
	}
	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)

	if err != nil {
		return "", fmt.Errorf("fail: %v", err)
	}

	defer resp.Body.Close()

	dataInBytes, err := ioutil.ReadAll(resp.Body)

	re := regexp.MustCompile("nRenewals=([0-9]+);")

	renewal := "0"
	found := re.FindStringSubmatch(string(dataInBytes))

	if len(found) > 1 {
		renewal = found[1]
	}

	crtUrl := "https://" + endpoint + "/certsrv/certnew.cer?ReqID=CACert&Enc=b64&Mode=inst&" + renewal
	req, _ = http.NewRequest("GET", crtUrl, nil)
	req.SetBasicAuth(username, password)
	resp, err = client.Do(req)

	defer resp.Body.Close()

	if err != nil {
		fmt.Println("fail: %v", err)
		return "", err
	}

	dataInBytes, err = ioutil.ReadAll(resp.Body)
	return string(dataInBytes), nil

}

func genCertRequest(csr string, endpoint string, username string, password string) (string, error) {
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
	req, _ := http.NewRequest("POST", "https://" + endpoint + "/certsrv/certfnsh.asp", strings.NewReader(data.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)

	defer resp.Body.Close()

	if err != nil {
		fmt.Println("fail: %v", err)
		return "", err
	}

	dataInBytes, err := ioutil.ReadAll(resp.Body)
	pageContent := string(dataInBytes)

	re := regexp.MustCompile("certnew.cer\\?ReqID=([0-9]*)&amp;Enc=b64")
	reqId := re.FindString(string(pageContent))
	var resUrl string

	if reqId == "" {
		fmt.Println("No matches.")
	} else {
		resUrl = "https://" + endpoint + "/certsrv/" + reqId
	}
	return resUrl, nil
}

func fetchCertResult(resUrl string, username string, password string) (string, error) {

	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
	req, _ := http.NewRequest("GET", resUrl, nil)
	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)

	defer resp.Body.Close()

	if err != nil {
		fmt.Println("fail: %v", err)
		return "", err
	}

	dataInBytes, err := ioutil.ReadAll(resp.Body)
	return string(dataInBytes), nil
}

func CreateCertificates(endpoint string, username string, password string, hosts string) {

	var privateKey bytes.Buffer
	keyBytes, err  := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("failed to generate rsa key")
	}

	pem.Encode(&privateKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyBytes)})

	caCrt, err := getCaCert(endpoint, username, password)
	if err != nil {
		log.Fatal("failed to fetch ca.crt")
	}
	fmt.Printf("ca.crt:\n%s\n", caCrt)

	template := generateTemplate(strings.Split(hosts, ","))

	csr, err := genCsr(template, keyBytes)
	if err != nil {
		fmt.Println("failed to generate CSR %v", err)
		return
	}

	resUrl, _ := genCertRequest(csr.String(), endpoint, username, password)
	resCrt, _ := fetchCertResult(resUrl, username, password)

	fmt.Printf("tls.key\n%s\n", privateKey.String())
	fmt.Printf("tls.crt\n%s\n", resCrt)
}
