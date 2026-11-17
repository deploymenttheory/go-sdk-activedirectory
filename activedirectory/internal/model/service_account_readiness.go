package model

import (
	"errors"
)

// Readiness mirrors Test-ADServiceAccount (issue #48).
//
// The reference reports whether this host can use the account, **not** whether
// the account is installed locally. In the lab a group managed account reported
// ready before it was ever installed and still ready after it was uninstalled,
// while a standalone account with a host association but no successful install
// reported not ready. Across every observed state the reference's result
// matched the native NetIsServiceAccount boolean exactly, so that is the
// reading this mirrors. See docs/research/local-service-accounts.md.

var ErrServiceAccountReadiness = errors.New("service account readiness could not be determined")

// ServiceAccountReadinessRequest selects one account. The account is resolved
// over the configured LDAP endpoint; the readiness reading is taken on the
// executing host.
type ServiceAccountReadinessRequest struct {
	Identity  Identity
	Partition string
}

// ServiceAccountReadinessResult reports the reading and everything it was
// derived from, so a false result is explainable rather than bare.
type ServiceAccountReadinessResult struct {
	Host      LocalServiceAccountHost
	Directory IdentityResult
	Domain    IdentityResult
	Account   *ServiceAccount
	// NativeAccountName is the name passed to the native API, without the
	// trailing dollar the directory stores.
	NativeAccountName string
	// Ready is the host's own answer. It is nil when the native reading did
	// not complete; an unknown reading is never reported as not ready.
	Ready *bool
	// Observed records that the native call completed and Ready is its result.
	Observed bool
}
