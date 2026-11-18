package client_test

import (
	"errors"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/errorcode"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/patype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func TestLoginRejectsEmptyPreauthenticationOfferWithoutPanic(t *testing.T) {
	info, err := asn1.Marshal(types.ETypeInfo2{})
	if err != nil {
		t.Fatal(err)
	}
	pa, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
	if err != nil {
		t.Fatal(err)
	}
	reply := messages.NewKRBError(types.NewPrincipalName(2, "krbtgt/EXAMPLE.TEST"), "EXAMPLE.TEST", errorcode.KDC_ERR_PREAUTH_REQUIRED, "owned-fixture")
	reply.EData = pa
	wire, err := reply.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, done := strictTicketKDC(t, wire)
	cfg := config.New()
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{{Realm: "EXAMPLE.TEST", KDC: []string{endpoint}}}
	cl := client.NewWithPassword("owned-fixture", "EXAMPLE.TEST", "fixture-only", cfg, client.StrictRealm("EXAMPLE.TEST"))
	t.Cleanup(cl.Destroy)
	if err := cl.Login(); err == nil {
		t.Fatal("empty preauthentication offer authenticated")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLoginOnlyPreservesProtocolRefusalFromCompleteValidKRBError(t *testing.T) {
	for _, scenario := range []string{"valid-refusal", "wrong-version", "trailing-envelope"} {
		t.Run(scenario, func(t *testing.T) {
			reply := messages.NewKRBError(types.NewPrincipalName(2, "krbtgt/EXAMPLE.TEST"), "EXAMPLE.TEST", errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN, "")
			if scenario == "wrong-version" {
				reply.PVNO = 4
			}
			wire, err := reply.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "trailing-envelope" {
				wire = append(wire, 0)
			}
			endpoint, done := strictTicketKDC(t, wire)
			cfg := config.New()
			cfg.LibDefaults.UDPPreferenceLimit = 1
			cfg.Realms = []config.Realm{{Realm: "EXAMPLE.TEST", KDC: []string{endpoint}}}
			cl := client.NewWithPassword("owned-fixture", "EXAMPLE.TEST", "fixture-only", cfg, client.StrictRealm("EXAMPLE.TEST"))
			t.Cleanup(cl.Destroy)
			err = cl.Login()
			var refusal messages.KRBError
			observed := errors.As(err, &refusal)
			if err == nil || observed != (scenario == "valid-refusal") || (observed && refusal.ErrorCode != errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN) {
				t.Fatalf("malformed KDC reply became a genuine protocol refusal: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
