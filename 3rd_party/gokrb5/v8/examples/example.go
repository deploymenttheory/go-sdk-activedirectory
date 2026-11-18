// Package examples provides simple examples of gokrb5 use.
//go:build examples
// +build examples

package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/jcmturner/goidentity/v6"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/keytab"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/service"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/spnego"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/test/testdata"
)

// This self-contained demonstration requires the upstream isolated test KDC.
// Its published fixture keys must never be installed in a real directory.
func main() {
	s := httpServer()
	defer s.Close()

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	exampleAESOnly(c)
	c.LibDefaults.NoAddresses = true
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	httpRequest(s.URL, s.Client(), cl)

	b, _ = hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	kt = keytab.New()
	kt.Unmarshal(b)
	c, _ = config.NewFromString(testdata.KRB5_CONF)
	exampleAESOnly(c)
	c.LibDefaults.NoAddresses = true
	cl = client.NewWithKeytab("testuser2", "TEST.GOKRB5", kt, c)
	httpRequest(s.URL, s.Client(), cl)
}

func httpRequest(url string, httpClient *http.Client, cl *client.Client) {
	clientCopy := *httpClient
	clientCopy.Jar = nil
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	httpClient = &clientCopy
	defer cl.Destroy()
	l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)

	err := cl.Login()
	if err != nil {
		l.Fatalf("Error on AS_REQ: %v\n", err)
	}
	r, _ := http.NewRequest("GET", url, nil)
	err = spnego.SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5")
	if err != nil {
		l.Fatalf("Error setting client SPNEGO header: %v", err)
	}
	httpResp, err := httpClient.Do(r)
	if err != nil {
		l.Fatalf("Request error: %v\n", err)
	}
	fmt.Fprintf(os.Stdout, "Response Code: %v\n", httpResp.StatusCode)
	defer httpResp.Body.Close()
	content, _ := io.ReadAll(httpResp.Body)
	fmt.Fprintf(os.Stdout, "Response Body:\n%s\n", content)
}

func httpServer() *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewUnstartedServer(spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l)))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	s.StartTLS()
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	creds := goidentity.FromHTTPRequestContext(r)
	fmt.Fprint(w, "<html>\n<p><h1>TEST.GOKRB5 Handler</h1></p>\n")
	if creds != nil && creds.Authenticated() {
		fmt.Fprintf(w, "<ul><li>Authenticed user: %s</li>\n", creds.UserName())
		fmt.Fprintf(w, "<li>User's realm: %s</li></ul>\n", creds.Domain())
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Authentication failed")
	}
	fmt.Fprint(w, "</html>")
	return
}

// Keep these demonstrations on the four supported AES Kerberos profiles.
func exampleAESOnly(conf *config.Config) {
	conf.LibDefaults.AllowWeakCrypto = false
	conf.LibDefaults.DefaultTktEnctypeIDs = []int32{20, 19, 18, 17}
	conf.LibDefaults.DefaultTGSEnctypeIDs = []int32{20, 19, 18, 17}
	conf.LibDefaults.PermittedEnctypeIDs = []int32{20, 19, 18, 17}
}
