package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
)

// Settings holds optional client settings.
type Settings struct {
	strictRealm             string
	ctx                     context.Context
	disablePAFXFast         bool
	assumePreAuthentication bool
	preAuthEType            int32
	logger                  *log.Logger
}

// StrictRealm binds ticket validation to an explicitly selected client/service
// realm. Referrals and alternate service identities are refused in this mode.
func StrictRealm(realm string) func(*Settings) {
	return func(s *Settings) { s.strictRealm = realm }
}

// WithContext bounds all KDC discovery, connection establishment and exchanges.
// Cancellation retires the owned KDC connection; it never changes credentials or realm.
func WithContext(ctx context.Context) func(*Settings) {
	return func(s *Settings) { s.ctx = ctx }
}

func (s *Settings) context() context.Context {
	if s != nil && s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// jsonSettings is used when marshaling the Settings details to JSON format.
type jsonSettings struct {
	DisablePAFXFast         bool `json:"DisablePAFXFast"`
	AssumePreAuthentication bool `json:"AssumePreAuthentication"`
}

// NewSettings creates a new client settings struct.
func NewSettings(settings ...func(*Settings)) *Settings {
	s := new(Settings)
	for _, set := range settings {
		set(s)
	}
	return s
}

// DisablePAFXFAST used to configure the client to not use PA_FX_FAST.
//
// s := NewSettings(DisablePAFXFAST(true))
func DisablePAFXFAST(b bool) func(*Settings) {
	return func(s *Settings) {
		s.disablePAFXFast = b
	}
}

// DisablePAFXFAST indicates is the client should disable the use of PA_FX_FAST.
func (s *Settings) DisablePAFXFAST() bool {
	return s.disablePAFXFast
}

// AssumePreAuthentication used to configure the client to assume pre-authentication is required.
//
// s := NewSettings(AssumePreAuthentication(true))
func AssumePreAuthentication(b bool) func(*Settings) {
	return func(s *Settings) {
		s.assumePreAuthentication = b
	}
}

// AssumePreAuthentication indicates if the client should proactively assume using pre-authentication.
func (s *Settings) AssumePreAuthentication() bool {
	return s.assumePreAuthentication
}

// Logger used to configure client with a logger.
//
// s := NewSettings(kt, Logger(l))
func Logger(l *log.Logger) func(*Settings) {
	return func(s *Settings) {
		s.logger = l
	}
}

// Logger returns the client logger instance.
func (s *Settings) Logger() *log.Logger {
	return s.logger
}

// Log will write to the service's logger if it is configured.
func (cl *Client) Log(format string, v ...interface{}) {
	if cl.settings.Logger() != nil {
		// Logging is best effort; the retained API cannot return a logger failure.
		_ = cl.settings.Logger().Output(2, fmt.Sprintf(format, v...))
	}
}

// JSON returns a JSON representation of the settings.
func (s *Settings) JSON() (string, error) {
	js := jsonSettings{
		DisablePAFXFast:         s.disablePAFXFast,
		AssumePreAuthentication: s.assumePreAuthentication,
	}
	b, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
