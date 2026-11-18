//go:build examples
// +build examples

package main

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
	"github.com/jcmturner/goidentity/v6"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/keytab"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/service"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/spnego"
)

const (
	port = ":9080"
)

func main() {
	keytabPath := flag.String("keytab", "", "Protected service keytab path")
	certPath := flag.String("tls-cert", "", "Service TLS certificate chain")
	keyPath := flag.String("tls-key", "", "Protected TLS private key path")
	flag.Parse()
	if *keytabPath == "" || *certPath == "" || *keyPath == "" {
		log.Fatal("keytab, tls-cert and tls-key are required")
	}
	// defer profile.Start(profile.TraceProfile).Stop()
	// Create logger
	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Load the service's keytab
	kt, err := keytab.Load(*keytabPath)
	if err != nil {
		log.Fatal("could not load private service keytab")
	}

	// Create the application's specific handler
	th := http.HandlerFunc(testAppHandler)

	// Set up handler mappings wrapping in the SPNEGOKRB5Authenticate handler wrapper
	mux := http.NewServeMux()
	mux.Handle("/", spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l), service.SessionManager(NewSessionMgr("gokrb5"))))

	// Start up the web server
	server := &http.Server{Addr: port, Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute}
	log.Fatal(server.ListenAndServeTLS(*certPath, *keyPath))
}

// Simple application specific handler
func testAppHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	creds := goidentity.FromHTTPRequestContext(r)
	fmt.Fprintf(w,
		`<html>
<h1>GOKRB5 Handler</h1>
<ul>
<li>Authenticed user: %s</li>
<li>User's realm: %s</li>
<li>Authn time: %v</li>
<li>Session ID: %s</li>
<ul>
</html>`,
		creds.UserName(),
		creds.Domain(),
		creds.AuthTime(),
		creds.SessionID(),
	)
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
