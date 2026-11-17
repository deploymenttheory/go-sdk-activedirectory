// Package activedirectory provides the activedirectory SDK interface.
package activedirectory

import (
	context "context"

	client "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/client"
	config "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
	accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
	authentication_policies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_policies"
	authentication_silos "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_silos"
	central_access "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
	claims "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/claims"
	computers "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/computers"
	directory_settings "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/directory_settings"
	discovery "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
	groups "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/groups"
	memberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
	object_restoration "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/object_restoration"
	operation_master "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/operation_master"
	organizational_units "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/organizational_units"
	password_policies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/password_policies"
	replication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
	resource_properties "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/resource_properties"
	service_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/service_accounts"
	users "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

// Client composes resource modules over one authenticated directory session.
// Close ends the session for every module. A Client must not be copied.
type Client struct {
	directory              *client.Client
	Directory              *client.Client
	Accounts               *accounts.Service
	AuthenticationPolicies *authentication_policies.Service
	AuthenticationSilos    *authentication_silos.Service
	CentralAccess          *central_access.Service
	Claims                 *claims.Service
	Computers              *computers.Service
	DirectorySettings      *directory_settings.Service
	Discovery              *discovery.Service
	Groups                 *groups.Service
	Memberships            *memberships.Service
	ObjectRestoration      *object_restoration.Service
	OperationMasters       *operation_master.Service
	OrganizationalUnits    *organizational_units.Service
	PasswordPolicies       *password_policies.Service
	Replication            *replication.Service
	ResourceProperties     *resource_properties.Service
	ServiceAccounts        *service_accounts.Service
	Users                  *users.Service
}

// Dial opens one native session and composes all resource modules around it.
func Dial(ctx context.Context, options config.Config) (*Client, error) {
	connection, err := client.Dial(ctx, options)
	if err != nil {
		return nil, err
	}
	return compose(connection), nil
}

func compose(connection *client.Client) *Client {
	return &Client{
		directory: connection, Directory: connection,
		Accounts:               accounts.New(connection),
		AuthenticationPolicies: authentication_policies.New(connection),
		AuthenticationSilos:    authentication_silos.New(connection),
		CentralAccess:          central_access.New(connection),
		Claims:                 claims.New(connection),
		Computers:              computers.New(connection),
		DirectorySettings:      directory_settings.New(connection),
		Discovery:              discovery.New(connection),
		Groups:                 groups.New(connection),
		Memberships:            memberships.New(connection),
		ObjectRestoration:      object_restoration.New(connection),
		OperationMasters:       operation_master.New(connection),
		OrganizationalUnits:    organizational_units.New(connection),
		PasswordPolicies:       password_policies.New(connection),
		Replication:            replication.New(connection),
		ResourceProperties:     resource_properties.New(connection),
		ServiceAccounts:        service_accounts.New(connection),
		Users:                  users.New(connection),
	}
}

// Close closes the shared session once and prevents subsequent native operations.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	return c.directory.Close()
}
