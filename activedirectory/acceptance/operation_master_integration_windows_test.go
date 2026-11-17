//go:build integration && windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_operation_master "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/operation_master"
)

// TestOperationMasterLive requires both the integration build tag and an
// explicit disposable-directory acknowledgement. It never provisions servers,
// stops holders, changes permissions, restores roles, or repeats failed writes.
func TestOperationMasterLive(t *testing.T) {
	if os.Getenv("AD_OPERATION_MASTER_LAB_ALLOW_CHANGES") != "disposable-forest" {
		t.Skip(
			"set AD_OPERATION_MASTER_LAB_ALLOW_CHANGES=disposable-forest to opt in to real directory changes",
		)
	}
	request := admodel.MoveOperationMasterRolesRequest{}
	for _, name := range strings.Split(os.Getenv("AD_OPERATION_MASTER_LAB_ROLES"), ",") {
		request.Roles = append(request.Roles, admodel.OperationMasterRole(strings.TrimSpace(name)))
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("AD_OPERATION_MASTER_LAB_ROLES must explicitly select valid roles: %v", err)
	}
	if value := os.Getenv("AD_OPERATION_MASTER_LAB_ALLOW_SEIZURE"); value != "" {
		if value != "disposable-forest-seizure" {
			t.Fatal(
				"AD_OPERATION_MASTER_LAB_ALLOW_SEIZURE must be empty or disposable-forest-seizure",
			)
		}
		request.Force = true
	}
	expected := admodel.OperationMasterStatus(os.Getenv("AD_OPERATION_MASTER_LAB_EXPECT"))
	if expected == "" {
		expected = admodel.OperationMasterTransferred
	}
	if expected != admodel.OperationMasterTransferred &&
		expected != admodel.OperationMasterSeized &&
		expected != admodel.OperationMasterAlreadyOwned {
		t.Fatal("AD_OPERATION_MASTER_LAB_EXPECT must be transferred, seized, or already-owned")
	}
	if expected == admodel.OperationMasterSeized && !request.Force {
		t.Fatal("expecting seizure requires the explicit seizure acknowledgement")
	}
	port := uint64(389)
	if value := os.Getenv("AD_OPERATION_MASTER_LAB_PORT"); value != "" {
		var err error
		port, err = strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			t.Fatal("AD_OPERATION_MASTER_LAB_PORT must be a positive 16-bit port")
		}
	}
	config := admodel.Config{
		Endpoint: admodel.Endpoint{
			Host: os.Getenv("AD_OPERATION_MASTER_LAB_TARGET"),
			Port: uint16(port),
		},
		Timeout: 5 * time.Minute,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client, err := adengine.Dial(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	root, err := client.RootDSE(ctx, admodel.RootDSEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf(
		"runtime=%s/%s target=%s:%d directory=%s force=%t expected=%s",
		runtime.GOOS,
		runtime.GOARCH,
		config.Endpoint.Host,
		config.Endpoint.Port,
		root.Capabilities().Type,
		request.Force,
		expected,
	)
	// Validate fixture ownership before submitting anything. A passing test
	// must exercise the requested action rather than a no-op on an owned role.
	err = adengine.InternalClientRead(client, ctx, func(bounded context.Context) error {
		target, plans, err := admodel.InternalPrepareOperationMasters(
			bounded,
			adengine.InternalClientSession(client),
			request.Roles,
		)
		if err != nil {
			return err
		}
		for _, plan := range plans {
			t.Logf(
				"before role=%s object=%s owner=%s",
				plan.InternalRole,
				plan.InternalDn,
				plan.InternalOwner,
			)
			if plan.InternalRidPool != nil {
				t.Logf("before RID pool=%d", *plan.InternalRidPool)
			}
			owned := strings.EqualFold(plan.InternalOwner, target)
			if owned != (expected == admodel.OperationMasterAlreadyOwned) {
				return admodel.ErrInvalidOperationMasterRequest
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("fixture does not permit the expected action; no writes submitted: %v", err)
	}
	result, moveErr := adservice_operation_master.New(client).MoveOperationMasterRoles(ctx, request)
	for _, outcome := range result.Outcomes {
		t.Logf(
			"after role=%s status=%s verified=%t owner=%s transfer=%d seizure=%d error=%v",
			outcome.Role,
			outcome.Status,
			outcome.Verified,
			outcome.ObservedOwnerDN,
			outcome.Transfer.State,
			outcome.Seizure.State,
			outcome.Err,
		)
		if outcome.ObservedRIDPool != nil {
			t.Logf("after RID pool=%d", *outcome.ObservedRIDPool)
		}
		if outcome.Status != expected || !outcome.Verified || outcome.Err != nil {
			t.Errorf("%s did not verify the expected %s action", outcome.Role, expected)
		}
	}
	if moveErr != nil {
		t.Fatalf(
			"request failed; reconcile role ownership and RID pool before another write: %v",
			moveErr,
		)
	}
}
