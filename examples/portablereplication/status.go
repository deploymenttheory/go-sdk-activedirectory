package main

import (
	"fmt"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

type status struct {
	Protocol  string       `json:"protocol"`
	Operation string       `json:"operation,omitempty"`
	Code      int64        `json:"code"`
	Server    *ad.Endpoint `json:"server,omitempty"`
}

// Traverse only SDK errors, recording codes rather than formatting private
// causes or caller paths. The bound also protects reporting from cyclic errors.
func statuses(err error) []status {
	var result []status
	type item struct {
		err    error
		server *ad.Endpoint
	}
	stack := []item{{err: err}}
	seen := make(map[string]bool)
	for visited := 0; len(stack) > 0 && visited < 1024; visited++ {
		entry := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		current := entry.err
		if current == nil {
			continue
		}
		var value status
		if source, ok := current.(*replication.ReplicationReadError); ok {
			server := source.Server
			entry.server = &server
		}
		switch e := current.(type) {
		case *discovery.NativeStatusError:
			value = status{Protocol: "win32-rpc", Operation: e.Operation, Code: int64(e.Code)}
		case *ad.KerberosError:
			if e.Code != 0 {
				value = status{Protocol: "kerberos", Code: int64(e.Code)}
			}
		case *ad.LDAPError:
			value = status{Protocol: "ldap", Code: int64(e.Code)}
		}
		if value.Protocol != "" {
			value.Server = entry.server
			key := fmt.Sprintf("%s/%s/%d/%v", value.Protocol, value.Operation, value.Code, value.Server)
			if !seen[key] {
				seen[key] = true
				result = append(result, value)
			}
		}
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			for _, cause := range joined.Unwrap() {
				stack = append(stack, item{err: cause, server: entry.server})
			}
		} else if wrapped, ok := current.(interface{ Unwrap() error }); ok {
			stack = append(stack, item{err: wrapped.Unwrap(), server: entry.server})
		}
	}
	return result
}
