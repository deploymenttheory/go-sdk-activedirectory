package model

import (
	"errors"
)

// ErrServiceAccountNotInstalled mirrors the reference refusal observed in the
// lab: "Referenced service account is not installed on this computer".
var ErrServiceAccountNotInstalled = errors.New("service account is not installed on this computer")

// ResetLocalServiceAccountPasswordRequest resets the host-held credential for
// one managed service account that is already installed here.
type ResetLocalServiceAccountPasswordRequest struct {
	Identity  Identity
	Partition string
	// Preview performs read-only preparation and the installed-state check
	// without calling the native reset.
	Preview bool
}
