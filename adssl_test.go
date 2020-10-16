package adssl

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew(t *testing.T) {
	srv := serverMock()
	defer srv.Close()

	s := Server{
		Endpoint: srv.URL,
		Username: "user",
		Password: "pass",
	}

	r := Request{
		CommonName:  "foo.bar",
		Country:     []string{"US"},
		Province:    []string{"New Jersey"},
		Locality:    []string{"Weehawken"},
		DNSNames:    "boo.bar",
		IPAddresses: "1.2.3.4",
	}

	testCase := struct {
		CaCert, Result string
	}{
		CaCert: "-----BEGIN CERTIFICATE-----CA-----END CERTIFICATE-----",
		Result: "-----BEGIN CERTIFICATE-----666-----END CERTIFICATE-----",
	}
	got, err := New(s, r)
	if err != nil {
		t.Fatal(err)
	}

	if got.CaCert != testCase.CaCert {
		t.Errorf("got %q, want %q", got.CaCert, testCase.CaCert)
	}
	if got.Result != testCase.Result {
		t.Errorf("got %q, want %q", got.Result, testCase.Result)
	}
}

func serverMock() *httptest.Server {
	handler := http.NewServeMux()
	handler.HandleFunc("/certsrv/certcarc.asp", certcarcMock)
	handler.HandleFunc("/certsrv/certfnsh.asp", certfnshMock)
	handler.HandleFunc("/certsrv/certnew.cer", certnewMock)

	srv := httptest.NewServer(handler)

	return srv
}

func certcarcMock(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("nRenewals=111;"))
}

func certfnshMock(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("certnew.cer?ReqID=666&amp;Enc=b64"))
}

func certnewMock(w http.ResponseWriter, r *http.Request) {
	switch r.FormValue("ReqID") {
	case "CACert":
		w.Write([]byte("-----BEGIN CERTIFICATE-----CA-----END CERTIFICATE-----"))
	case "666":
		w.Write([]byte("-----BEGIN CERTIFICATE-----666-----END CERTIFICATE-----"))
	}
}
