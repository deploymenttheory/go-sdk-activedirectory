package object_restoration

import (
	adclient "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/client"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
)

// Service owns the typed workflows for this resource family over one shared session.
type Service struct{ client *adengine.Client }

// New binds this resource family to the owning SDK session.
func New(client *adclient.Client) *Service { return &Service{client: client} }

func (s *Service) engine() *adengine.Client {
	if s == nil {
		return nil
	}
	return s.client
}
