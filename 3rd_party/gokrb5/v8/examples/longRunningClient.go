//go:build examples
// +build examples

package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/keytab"
)

func main() {
	configPath := flag.String("config", "", "Caller-owned krb5.conf with explicit realm/KDC and AES encryption types")
	keytabPath := flag.String("keytab", "", "Protected caller-owned keytab path")
	username := flag.String("user", "", "Kerberos account name")
	realm := flag.String("realm", "", "Kerberos realm")
	serviceName := flag.String("spn", "", "Explicit service principal")
	flag.Parse()
	if *configPath == "" || *keytabPath == "" || *username == "" || *realm == "" || *serviceName == "" {
		log.Fatal("explicit config, keytab, user, realm and service principal are required")
	}
	l := log.New(os.Stderr, "GOKRB5 Client: ", log.LstdFlags)

	// defer profile.Start(profile.TraceProfile).Stop()
	// Load the keytab
	kt, err := keytab.Load(*keytabPath)
	if err != nil {
		l.Fatalf("could not load client keytab: %v", err)
	}

	// Load the client krb5 config
	conf, err := config.Load(*configPath)
	if err != nil {
		l.Fatalf("could not load krb5.conf: %v", err)
	}

	// Create the client with the keytab
	exampleAESOnly(conf)
	cl := client.NewWithKeytab(*username, *realm, kt, conf, client.Logger(l), client.DisablePAFXFAST(true))
	defer cl.Destroy()

	// Log in the client
	err = cl.Login()
	if err != nil {
		l.Fatalf("could not login client: %v", err)
	}

	for {
		_, _, err := cl.GetServiceTicket(*serviceName)
		if err != nil {
			l.Printf("failed to get service ticket: %v\n", err)
		}
		time.Sleep(time.Minute * 5)
	}
}

// Keep these demonstrations on the four supported AES Kerberos profiles.
func exampleAESOnly(conf *config.Config) {
	conf.LibDefaults.AllowWeakCrypto = false
	conf.LibDefaults.DefaultTktEnctypeIDs = []int32{20, 19, 18, 17}
	conf.LibDefaults.DefaultTGSEnctypeIDs = []int32{20, 19, 18, 17}
	conf.LibDefaults.PermittedEnctypeIDs = []int32{20, 19, 18, 17}
}
