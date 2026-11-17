package engine

import (
	"context"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// InternalDirectoryServiceFields supports internal workflows and deliberately malformed test fixtures.
type InternalDirectoryServiceFields struct {
	Client *Client
}

func InternalDirectoryServiceFromFields(fields InternalDirectoryServiceFields) DirectoryService {
	return DirectoryService{client: fields.Client}
}

func InternalDirectoryServicePointerFromFields(
	fields InternalDirectoryServiceFields,
) *DirectoryService {
	return &DirectoryService{client: fields.Client}
}
func InternalDirectoryServiceClient(value DirectoryService) *Client { return value.client }

func InternalDirectoryServiceClientPointer(
	value *DirectoryService,
) **Client {
	return &value.client
}

// InternalClientFields supports internal workflows and deliberately malformed test fixtures.
type InternalClientFields struct {
	Config   admodel.Config
	Session  admodel.InternalDirectorySession
	Gate     chan struct{}
	Lifetime context.Context
	Cancel   context.CancelCauseFunc
	CloseErr error
}

func InternalClientFromFields(fields InternalClientFields) Client {
	return Client{
		config:   fields.Config,
		session:  fields.Session,
		gate:     fields.Gate,
		lifetime: fields.Lifetime,
		cancel:   fields.Cancel,
		closeErr: fields.CloseErr,
	}
}

func InternalClientPointerFromFields(fields InternalClientFields) *Client {
	return &Client{
		config:   fields.Config,
		session:  fields.Session,
		gate:     fields.Gate,
		lifetime: fields.Lifetime,
		cancel:   fields.Cancel,
		closeErr: fields.CloseErr,
	}
}
func InternalClientConfig(value *Client) admodel.Config                    { return value.config }
func InternalClientConfigPointer(value *Client) *admodel.Config            { return &value.config }
func InternalClientSession(value *Client) admodel.InternalDirectorySession { return value.session }
func InternalClientSessionPointer(value *Client) *admodel.InternalDirectorySession {
	return &value.session
}
func InternalClientGate(value *Client) chan struct{}                     { return value.gate }
func InternalClientGatePointer(value *Client) *chan struct{}             { return &value.gate }
func InternalClientLifetime(value *Client) context.Context               { return value.lifetime }
func InternalClientLifetimePointer(value *Client) *context.Context       { return &value.lifetime }
func InternalClientCancel(value *Client) context.CancelCauseFunc         { return value.cancel }
func InternalClientCancelPointer(value *Client) *context.CancelCauseFunc { return &value.cancel }
func InternalClientCloseErr(value *Client) error                         { return value.closeErr }
func InternalClientCloseErrPointer(value *Client) *error                 { return &value.closeErr }
