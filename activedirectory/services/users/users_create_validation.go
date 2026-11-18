package users

import admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"

// prepareUserCreation validates input and defaults the object class before any
// directory operation. Directory-specific capability checks follow the RootDSE read.
func prepareUserCreation(request CreateUserRequest) (CreateUserRequest, bool, error) {
	if err := admodel.InternalValidateAccountCreationOptions(
		request.Parent,
		request.Options,
	); err != nil {
		return request, false, err
	}
	if request.Options.ExpectedVersion != nil {
		return request, false, admodel.ErrObjectControlUnsupported
	}
	if request.Name == "" || !admodel.InternalValidDirectoryText(request.Name) {
		return request, false, admodel.ErrInvalidUser
	}
	if request.Class == "" {
		request.Class = "user"
	}
	if request.Class != "user" && request.Class != "inetOrgPerson" {
		return request, false, admodel.ErrInvalidUser
	}
	wantEnabled := request.Properties.Enabled != nil && *request.Properties.Enabled
	withoutPassword := request.Properties.PasswordNotRequired != nil &&
		*request.Properties.PasswordNotRequired
	if wantEnabled && request.InitialPassword == nil && !withoutPassword {
		return request, false, admodel.ErrInvalidUser
	}
	if request.InitialPassword != nil {
		if err := admodel.InternalValidatePasswordBytes(request.InitialPassword); err != nil {
			return request, false, err
		}
	}
	// Validate text/raw conflicts before any stage. Directory-specific flag
	// mapping is finalized after reading the selected connection's RootDSE.
	if _, err := admodel.InternalUserCreationAttributes(
		request,
		admodel.DirectoryADDS,
	); err != nil {
		return request, false, err
	}
	return request, wantEnabled, nil
}
