//go:build examples
// +build examples

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/keytab"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/spnego"
)

func main() {
	configPath := flag.String("config", "", "Caller-owned krb5.conf with explicit realm/KDC and AES encryption types")
	keytabPath := flag.String("keytab", "", "Protected caller-owned keytab path")
	username := flag.String("user", "", "Kerberos account name")
	realm := flag.String("realm", "", "Kerberos realm")
	target := flag.String("url", "", "HTTPS service URL with a trusted matching certificate")
	flag.Parse()
	endpoint, err := url.Parse(*target)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		*configPath == "" || *keytabPath == "" || *username == "" || *realm == "" {
		log.Fatal("explicit config, keytab, user, realm and HTTPS URL are required")
	}
	kt, err := keytab.Load(*keytabPath)
	if err != nil {
		log.Fatal("could not load private keytab")
	}
	conf, err := config.Load(*configPath)
	if err != nil {
		log.Fatal("could not load explicit Kerberos configuration")
	}
	exampleAESOnly(conf)
	cl := client.NewWithKeytab(*username, *realm, kt, conf, client.DisablePAFXFAST(true))
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		log.Fatal("Kerberos login failed")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		log.Fatal("could not create HTTPS request")
	}
	spnegoClient := spnego.NewClient(cl, httpClient, "HTTP/"+endpoint.Hostname())
	response, err := spnegoClient.Do(request)
	if err != nil {
		log.Fatal("authenticated HTTPS request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		log.Fatal("could not read HTTPS response")
	}
	fmt.Printf("HTTP %d\n%s\n", response.StatusCode, body)
}

// Keep these demonstrations on the four supported AES Kerberos profiles.
func exampleAESOnly(conf *config.Config) {
	conf.LibDefaults.AllowWeakCrypto = false
	conf.LibDefaults.DefaultTktEnctypeIDs = []int32{20, 19, 18, 17}
	conf.LibDefaults.DefaultTGSEnctypeIDs = []int32{20, 19, 18, 17}
	conf.LibDefaults.PermittedEnctypeIDs = []int32{20, 19, 18, 17}
}
