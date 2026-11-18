package shared

import admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"

// SessionProtection reports measured TLS/SASL/authentication facts. Complete must
// be true and the accompanying error nil before callers rely on the observation.
type SessionProtection = admodel.SessionProtection

// BackendUnavailableError identifies an unavailable selected implementation,
// separately from DirectoryCapabilityError on the connected server.
type BackendUnavailableError = admodel.BackendUnavailableError

// ErrBackendUnavailable identifies unavailable backend or host mechanisms.
var ErrBackendUnavailable = admodel.ErrBackendUnavailable
