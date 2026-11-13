// The default invocation reads policy. Supplying any policy option performs
// one update; use update options only in a disposable qualification directory.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func intervalText(value ad.PolicyInterval) string {
	if value == ad.PolicyNever {
		return "never"
	}
	if duration, err := value.Duration(); err == nil {
		return duration.String()
	}
	return fmt.Sprintf("%d ticks of 100ns", value)
}

func printPolicy(policy ad.DomainPasswordPolicy) {
	fmt.Printf("Domain: %s\n", policy.DomainDN)
	fmt.Printf("Password ages: min=%s max=%s\n", intervalText(policy.MinPasswordAge), intervalText(policy.MaxPasswordAge))
	fmt.Printf("Lockout: threshold=%d duration=%s observation=%s\n", policy.LockoutThreshold, intervalText(policy.LockoutDuration), intervalText(policy.LockoutObservationWindow))
	fmt.Printf("Minimum length=%d history=%d complexity=%t reversible encryption=%t pwdProperties=0x%08x\n", policy.MinPasswordLength, policy.PasswordHistoryCount, policy.ComplexityEnabled(), policy.ReversibleEncryptionEnabled(), policy.PasswordProperties)
}

func run(server, domain string, update ad.DomainPasswordPolicyUpdate, change bool) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}, Partition: domain})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	if !change {
		policy, err := client.DefaultDomainPasswordPolicy(ctx)
		if err == nil {
			printPolicy(policy)
		}
		return err
	}
	result, err := client.UpdateDefaultDomainPasswordPolicy(ctx, update)
	fmt.Printf("Write state=%d verified=%t\n", result.WriteState, result.Verified)
	if result.Verified {
		printPolicy(result.After)
	}
	return err
}

func main() {
	server := flag.String("server", "", "connected domain controller FQDN")
	domain := flag.String("domain", "", "optional expected domain DN; must match the server's default domain")
	update := ad.DomainPasswordPolicyUpdate{}
	change := false
	for _, field := range []struct {
		name   string
		target **ad.PolicyInterval
	}{
		{"max-age", &update.MaxPasswordAge}, {"min-age", &update.MinPasswordAge},
		{"lockout-duration", &update.LockoutDuration}, {"lockout-window", &update.LockoutObservationWindow},
	} {
		flag.Func(field.name, "update interval (e.g. 720h, 30m, 0, or never)", func(text string) error {
			value := ad.PolicyNever
			if text != "never" {
				duration, err := time.ParseDuration(text)
				if err != nil {
					return err
				}
				value, err = ad.PolicyIntervalFromDuration(duration)
				if err != nil {
					return err
				}
			}
			*field.target = &value
			change = true
			return nil
		})
	}
	for _, field := range []struct {
		name   string
		target **uint16
	}{
		{"min-length", &update.MinPasswordLength}, {"history", &update.PasswordHistoryCount}, {"threshold", &update.LockoutThreshold},
	} {
		flag.Func(field.name, "update the selected count (explicit zero is supported)", func(text string) error {
			value, err := strconv.ParseUint(text, 10, 16)
			if err != nil {
				return err
			}
			count := uint16(value)
			*field.target = &count
			change = true
			return nil
		})
	}
	for _, field := range []struct {
		name   string
		target **bool
	}{
		{"complexity", &update.ComplexityEnabled}, {"reversible-encryption", &update.ReversibleEncryptionEnabled},
	} {
		flag.Func(field.name, "update flag: true or false", func(text string) error {
			value, err := strconv.ParseBool(text)
			if err != nil {
				return err
			}
			*field.target = &value
			change = true
			return nil
		})
	}
	flag.Parse()
	if err := run(*server, *domain, update, change); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
