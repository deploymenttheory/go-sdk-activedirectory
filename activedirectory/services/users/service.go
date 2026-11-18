package users

import (
	adclient "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/client"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
)

// Service owns the typed workflows for this resource family over one shared session.
type Service struct{ client *adengine.Client }

// New returns the users service bound to the supplied directory client.
// The service shares the client's connection and lifetime; it does not open a separate session.
func New(client *adclient.Client) *Service { return &Service{client: client} }

// engine returns the shared directory client, or nil for an uninitialized service.
func (s *Service) engine() *adengine.Client {
	if s == nil {
		return nil
	}
	return s.client
}
