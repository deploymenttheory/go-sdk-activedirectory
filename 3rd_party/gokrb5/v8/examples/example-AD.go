//go:build examples
// +build examples

package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/gorilla/sessions"
	"github.com/jcmturner/goidentity/v6"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/credentials"
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
	fmt.Printf("Listening on %s\n", s.URL)
	l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_USER_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	exampleAESOnly(c)
	cl := client.NewWithKeytab("testuser1", "USER.GOKRB5", kt, c, client.DisablePAFXFAST(true), client.Logger(l))
	httpRequest(s.URL, s.Client(), cl)

	b, _ = hex.DecodeString(testdata.KEYTAB_TESTUSER2_USER_GOKRB5)
	kt = keytab.New()
	kt.Unmarshal(b)
	c, _ = config.NewFromString(testdata.KRB5_CONF)
	exampleAESOnly(c)
	cl = client.NewWithKeytab("testuser2", "USER.GOKRB5", kt, c, client.DisablePAFXFAST(true), client.Logger(l))
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

	spnegoCl := spnego.NewClient(cl, httpClient, "HTTP/host.res.gokrb5")

	// Make the request for the first time with no session
	r, _ := http.NewRequest("GET", url, nil)
	httpResp, err := spnegoCl.Do(r)
	if err != nil {
		l.Fatalf("error making request: %v", err)
	}
	fmt.Fprintf(os.Stdout, "Response Code: %v\n", httpResp.StatusCode)
	defer httpResp.Body.Close()
	content, _ := io.ReadAll(httpResp.Body)
	fmt.Fprintf(os.Stdout, "Response Body:\n%s\n", content)

	// Make the request again which should use the session
	if err := httpResp.Body.Close(); err != nil {
		l.Fatal("could not close response")
	}
	httpResp, err = spnegoCl.Do(r)
	if err != nil {
		l.Fatalf("error making request: %v", err)
	}
	fmt.Fprintf(os.Stdout, "Response Code: %v\n", httpResp.StatusCode)
	defer httpResp.Body.Close()
	content, _ = io.ReadAll(httpResp.Body)
	fmt.Fprintf(os.Stdout, "Response Body:\n%s\n", content)
}

func httpServer() *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, _ := hex.DecodeString(testdata.KEYTAB_SYSHTTP_RES_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewUnstartedServer(spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l),
		service.KeytabPrincipal("sysHTTP"), service.SessionManager(NewSessionMgr("gokrb5"))))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	s.StartTLS()
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	creds := goidentity.FromHTTPRequestContext(r)
	fmt.Fprint(w, "<html>\n<p><h1>GOKRB5 Handler</h1></p>\n")
	if creds != nil && creds.Authenticated() {
		fmt.Fprintf(w, "<ul><li>Authenticed user: %s</li>\n", creds.UserName())
		fmt.Fprintf(w, "<li>User's realm: %s</li>\n", creds.Domain())
		fmt.Fprint(w, "<li>Authz Attributes (Group Memberships):</li><ul>\n")
		for _, s := range creds.AuthzAttributes() {
			fmt.Fprintf(w, "<li>%v</li>\n", s)
		}
		fmt.Fprint(w, "</ul>\n")
		if ADCredsJSON, ok := creds.Attributes()[credentials.AttributeKeyADCredentials]; ok {
			//ADCreds := new(credentials.ADCredentials)
			ADCreds := ADCredsJSON.(credentials.ADCredentials)
			// err := json.Unmarshal(aj, ADCreds)
			// if err == nil {
			// Now access the fields of the ADCredentials struct. For example:
			fmt.Fprintf(w, "<li>EffectiveName: %v</li>\n", ADCreds.EffectiveName)
			fmt.Fprintf(w, "<li>FullName: %v</li>\n", ADCreds.FullName)
			fmt.Fprintf(w, "<li>UserID: %v</li>\n", ADCreds.UserID)
			fmt.Fprintf(w, "<li>PrimaryGroupID: %v</li>\n", ADCreds.PrimaryGroupID)
			fmt.Fprintf(w, "<li>Group SIDs: %v</li>\n", ADCreds.GroupMembershipSIDs)
			fmt.Fprintf(w, "<li>LogOnTime: %v</li>\n", ADCreds.LogOnTime)
			fmt.Fprintf(w, "<li>LogOffTime: %v</li>\n", ADCreds.LogOffTime)
			fmt.Fprintf(w, "<li>PasswordLastSet: %v</li>\n", ADCreds.PasswordLastSet)
			fmt.Fprintf(w, "<li>LogonServer: %v</li>\n", ADCreds.LogonServer)
			fmt.Fprintf(w, "<li>LogonDomainName: %v</li>\n", ADCreds.LogonDomainName)
			fmt.Fprintf(w, "<li>LogonDomainID: %v</li>\n", ADCreds.LogonDomainID)
			//}
		}
		fmt.Fprint(w, "</ul>")
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Authentication failed")
	}
	fmt.Fprint(w, "</html>")
	return
}

type SessionMgr struct {
	skey       []byte
	store      sessions.Store
	cookieName string
}

func NewSessionMgr(cookieName string) SessionMgr {
	skey := make([]byte, 32)
	if _, err := rand.Read(skey); err != nil {
		log.Fatal("session key generation failed")
	}
	store := sessions.NewCookieStore(skey)
	store.Options = &sessions.Options{Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	return SessionMgr{
		skey:       skey,
		store:      store,
		cookieName: cookieName,
	}
}

func (smgr SessionMgr) Get(r *http.Request, k string) ([]byte, error) {
	s, err := smgr.store.Get(r, smgr.cookieName)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errors.New("nil session")
	}
	b, ok := s.Values[k].([]byte)
	if !ok {
		return nil, fmt.Errorf("could not get bytes held in session at %s", k)
	}
	return b, nil
}

func (smgr SessionMgr) New(w http.ResponseWriter, r *http.Request, k string, v []byte) error {
	s, err := smgr.store.New(r, smgr.cookieName)
	if err != nil {
		return fmt.Errorf("could not get new session from session manager: %v", err)
	}
	s.Values[k] = v
	return s.Save(r, w)
}

// Keep these demonstrations on the four supported AES Kerberos profiles.
func exampleAESOnly(conf *config.Config) {
	conf.LibDefaults.AllowWeakCrypto = false
	conf.LibDefaults.DefaultTktEnctypeIDs = []int32{20, 19, 18, 17}
	conf.LibDefaults.DefaultTGSEnctypeIDs = []int32{20, 19, 18, 17}
	conf.LibDefaults.PermittedEnctypeIDs = []int32{20, 19, 18, 17}
}
