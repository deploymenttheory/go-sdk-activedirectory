// Generate DCCloneConfig.xml. Online execution prepares the local source DC;
// -offline explicitly skips prerequisites and replaces output in -directory.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/dccloning"
)

func main() {
	var options dccloning.ConfigOptions
	var ipv4DNS, ipv6DNS string
	flag.StringVar(&options.Directory, "directory", "", "existing output directory (required offline; online defaults to DSA Working Directory)")
	flag.BoolVar(&options.Offline, "offline", false, "skip all prerequisites and replace existing DCCloneConfig.xml")
	flag.StringVar(&options.Configuration.ComputerName, "computer-name", "", "optional clone computer name")
	flag.StringVar(&options.Configuration.SiteName, "site", "", "optional clone site name")
	flag.BoolVar(&options.Configuration.Static, "static", false, "use static settings for configured IP families")
	flag.StringVar(&options.Configuration.IPv4Address, "ipv4-address", "", "static clone IPv4 address")
	flag.StringVar(&options.Configuration.IPv4SubnetMask, "ipv4-mask", "", "static clone IPv4 subnet mask")
	flag.StringVar(&options.Configuration.IPv4DefaultGateway, "ipv4-gateway", "", "optional static IPv4 gateway")
	flag.StringVar(&ipv4DNS, "ipv4-dns", "", "one to four comma-separated IPv4 DNS resolvers")
	flag.StringVar(&ipv6DNS, "ipv6-dns", "", "one to four comma-separated IPv6 DNS resolvers")
	flag.DurationVar(&options.Timeout, "timeout", 30*time.Second, "whole-operation deadline")
	encodeOnly := flag.Bool("encode-only", false, "write validated XML to stdout without host checks or filesystem changes")
	flag.Parse()
	if ipv4DNS != "" {
		options.Configuration.IPv4DNSResolvers = strings.Split(ipv4DNS, ",")
	}
	if ipv6DNS != "" {
		options.Configuration.IPv6DNSResolvers = strings.Split(ipv6DNS, ",")
	}
	if *encodeOnly {
		data, err := dccloning.EncodeCloneConfiguration(options.Configuration)
		if err == nil {
			_, err = os.Stdout.Write(data)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	result, err := dccloning.GenerateConfig(context.Background(), options)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if encodeErr := encoder.Encode(result); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
