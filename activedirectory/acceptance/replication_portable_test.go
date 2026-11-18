package acceptance

import (
	"context"
	"errors"
	"math"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableReplicationPartnerObservationsAreCopiedWithoutLosingNulls(t *testing.T) {
	empty, name := "", "CN=NTDS Settings,CN=DC2"
	raw := admodel.InternalPortableReplicationReply{
		Kind: admodel.InternalReplicationNeighbors, Present: true, Count: 1,
		Neighbors: []admodel.InternalPortableReplicationNeighbor{{
			PartitionDN: &empty, PartnerDN: &name,
			PartnerGUID:  [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			ReplicaFlags: 0x80000000, LastObjectUSN: -1, AttributeFilterUSN: math.MinInt64,
			LastSuccess: 0, LastAttempt: 116444736001234567, LastResult: 0xfedcba98, ConsecutiveFailures: 7,
		}},
	}
	reply := admodel.InternalDecodePortableReplicationObservation(context.Background(), raw.Kind, raw)
	if reply.InternalErr != nil || len(reply.InternalData.InternalPartners) != 1 {
		t.Fatalf("valid partner rejected: %v", reply.InternalErr)
	}
	got := reply.InternalData.InternalPartners[0]
	if got.PartitionDN == nil || *got.PartitionDN != "" || got.PartnerAddress != nil || got.TransportDN != nil ||
		got.PartnerDN == &name || *got.PartnerDN != name || got.Direction != admodel.ReplicationInbound {
		t.Fatal("nullable or copied text changed")
	}
	if *got.PartnerGUID != "04030201-0605-0807-090a-0b0c0d0e0f10" ||
		*got.PartitionGUID != "00000000-0000-0000-0000-000000000000" || *got.ReplicaFlags != 0x80000000 ||
		*got.LastObjectUSN != -1 || *got.AttributeFilterUSN != math.MinInt64 || *got.LastResult != 0xfedcba98 {
		t.Fatal("GUID byte order, signed USNs or unknown status/flags were lost")
	}
	if got.LastSuccess.Ticks == nil || *got.LastSuccess.Ticks != 0 || got.LastSuccess.UTC != nil ||
		got.LastAttempt.UTC == nil || got.LastAttempt.UTC.Nanosecond() != 123456700 {
		t.Fatal("reported zero or FILETIME precision changed")
	}
	name = "changed caller buffer"
	raw.Neighbors[0].LastResult = 0
	raw.Neighbors[0].PartnerGUID[0] = 0
	if *got.PartnerDN != "CN=NTDS Settings,CN=DC2" || *got.LastResult != 0xfedcba98 ||
		*got.PartnerGUID != "04030201-0605-0807-090a-0b0c0d0e0f10" {
		t.Fatal("projection retained mutable transport-owned values")
	}
}

func TestPortableReplicationFailureCategoriesKeepUnavailableErrorAndTimeSemantics(t *testing.T) {
	for _, kind := range []admodel.InternalReplicationInfo{admodel.InternalReplicationConnectFailures, admodel.InternalReplicationLinkFailures} {
		raw := admodel.InternalPortableReplicationReply{
			Kind: kind, Present: true, Count: 1,
			Failures: []admodel.InternalPortableReplicationFailure{{Time: 9, FailureCount: 4, LastResult: 0}},
		}
		reply := admodel.InternalDecodePortableReplicationObservation(context.Background(), kind, raw)
		if reply.InternalErr != nil || len(reply.InternalData.InternalFailures) != 1 {
			t.Fatalf("failure with unavailable status discarded: %v", reply.InternalErr)
		}
		got := reply.InternalData.InternalFailures[0]
		want := admodel.ReplicationConnectionFailure
		if kind == admodel.InternalReplicationLinkFailures {
			want = admodel.ReplicationLinkFailure
		}
		if got.Kind != want || got.LastResult != 0 || got.LastResultAvailable || got.FailureCount != 4 ||
			got.Time.Ticks == nil || *got.Time.Ticks != 9 || got.PartnerDN != nil {
			t.Fatal("connection/link meaning or unavailable error code changed")
		}
	}
}

func TestPortableReplicationQueuePreservesServerOrderAndUnknownOperation(t *testing.T) {
	empty := ""
	raw := admodel.InternalPortableReplicationReply{
		Kind: admodel.InternalReplicationPendingOperations, Present: true, Count: 2,
		Operations: []admodel.InternalPortableReplicationOperation{
			{SerialNumber: 77, Priority: 1, Type: 0xffff, Options: 0x80000000, PartnerDN: &empty},
			{SerialNumber: 1, Priority: 99},
		},
	}
	reply := admodel.InternalDecodePortableReplicationObservation(context.Background(), raw.Kind, raw)
	got := reply.InternalData
	if reply.InternalErr != nil || len(got.InternalOperations) != 2 || got.InternalOperations[0].SerialNumber != 77 ||
		got.InternalOperations[1].SerialNumber != 1 || got.InternalOperations[0].Type != 0xffff ||
		got.InternalOperations[0].Options != 0x80000000 || got.InternalOperations[0].PartnerDN == nil ||
		*got.InternalOperations[0].PartnerDN != "" || got.InternalOperations[1].PartnerDN != nil {
		t.Fatalf("ordered queue projection changed: %v", reply.InternalErr)
	}
	if got.InternalStarted.Ticks == nil || *got.InternalStarted.Ticks != 0 || got.InternalStarted.UTC != nil {
		t.Fatal("reported zero current-operation timestamp became unreported")
	}
}

func TestPortableReplicationRefusalMissingAndConfirmedEmptyRemainDistinct(t *testing.T) {
	kind := admodel.InternalReplicationConnectFailures
	empty := admodel.InternalDecodePortableReplicationObservation(context.Background(), kind,
		admodel.InternalPortableReplicationReply{Kind: kind, Present: true})
	if state := empty.InternalState(); !state.Available || !state.Complete || state.Error != nil {
		t.Fatal("successful counted empty collection lost")
	}
	missing := admodel.InternalDecodePortableReplicationObservation(context.Background(), kind,
		admodel.InternalPortableReplicationReply{Kind: kind})
	if state := missing.InternalState(); state.Available || state.Complete || !errors.Is(state.Error, admodel.ErrInvalidResult) {
		t.Fatal("missing output pointer became confirmed empty")
	}
	for _, status := range []uint32{5, 8453, 0xfedcba98} {
		refusal := admodel.InternalDecodePortableReplicationObservation(context.Background(), kind,
			admodel.InternalPortableReplicationReply{Kind: kind, Status: status})
		var code *admodel.NativeStatusError
		if state := refusal.InternalState(); state.Complete || state.Available || !errors.As(state.Error, &code) ||
			code.Code != status || code.Operation != "IDL_DRSGetReplInfo" {
			t.Fatalf("exact DRS refusal lost: %v", state.Error)
		}
	}
}

func TestPortableReplicationInvalidUnionAndIncompletePrefix(t *testing.T) {
	kind := admodel.InternalReplicationPendingOperations
	for _, test := range []struct {
		name     string
		raw      admodel.InternalPortableReplicationReply
		wantRows int
	}{
		{"wrong-kind", admodel.InternalPortableReplicationReply{Kind: admodel.InternalReplicationNeighbors, Present: true}, 0},
		{"mixed-union", admodel.InternalPortableReplicationReply{
			Kind: kind, Present: true, Count: 1,
			Operations: []admodel.InternalPortableReplicationOperation{{}}, Failures: []admodel.InternalPortableReplicationFailure{{}},
		}, 0},
		{"count-limit", admodel.InternalPortableReplicationReply{Kind: kind, Present: true, Count: 1<<20 + 1}, 0},
		{"truncated-prefix", admodel.InternalPortableReplicationReply{
			Kind: kind, Present: true, Count: 2,
			Operations: []admodel.InternalPortableReplicationOperation{{SerialNumber: 41}},
		}, 1},
		{"extra-record", admodel.InternalPortableReplicationReply{
			Kind: kind, Present: true, Count: 1,
			Operations: []admodel.InternalPortableReplicationOperation{{SerialNumber: 41}, {SerialNumber: 42}},
		}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			reply := admodel.InternalDecodePortableReplicationObservation(context.Background(), kind, test.raw)
			if !errors.Is(reply.InternalErr, admodel.ErrInvalidResult) || len(reply.InternalData.InternalOperations) != test.wantRows ||
				reply.InternalState().Complete {
				t.Fatalf("malformed observation became complete: %v", reply.InternalErr)
			}
			if test.wantRows != 0 && (reply.InternalData.InternalOperations[0].SerialNumber != 41 || !reply.InternalState().Available) {
				t.Fatal("valid incomplete prefix was discarded")
			}
		})
	}
}

func TestPortableReplicationMalformedTextRetainsOtherObservedFields(t *testing.T) {
	bad := "CN=bad\x00name"
	raw := admodel.InternalPortableReplicationReply{
		Kind: admodel.InternalReplicationLinkFailures, Present: true, Count: 1,
		Failures: []admodel.InternalPortableReplicationFailure{{PartnerDN: &bad, FailureCount: 7, LastResult: 1722}},
	}
	reply := admodel.InternalDecodePortableReplicationObservation(context.Background(), raw.Kind, raw)
	if !errors.Is(reply.InternalErr, admodel.ErrInvalidResult) || !reply.InternalState().Available || reply.InternalState().Complete ||
		len(reply.InternalData.InternalFailures) != 1 || reply.InternalData.InternalFailures[0].PartnerDN != nil ||
		reply.InternalData.InternalFailures[0].LastResult != 1722 {
		t.Fatal("malformed text erased other fields or became successful")
	}
}

func TestPortableReplicationCancellationDoesNotEraseConfirmedRefusal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	kind := admodel.InternalReplicationConnectFailures
	reply := admodel.InternalDecodePortableReplicationObservation(ctx, kind, admodel.InternalPortableReplicationReply{Kind: kind, Status: 8453})
	var status *admodel.NativeStatusError
	if !errors.Is(reply.InternalErr, context.Canceled) || !errors.As(reply.InternalErr, &status) || status.Code != 8453 ||
		reply.InternalState().Complete {
		t.Fatal("cancellation replaced the independently observed server status")
	}
}

func TestPortableReplicationCategoryRefusalRetainsConfirmedEmptySibling(t *testing.T) {
	reader := InternalReplicationTestReader(func(
		ctx context.Context, _ admodel.Config, _ admodel.RootDSE, _ []byte, _ admodel.InternalReplicationRequest,
	) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
		connection := admodel.InternalReplicationConnectFailures
		link := admodel.InternalReplicationLinkFailures
		return map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply{
			connection: admodel.InternalDecodePortableReplicationObservation(ctx, connection,
				admodel.InternalPortableReplicationReply{Kind: connection, Present: true}),
			link: admodel.InternalDecodePortableReplicationObservation(ctx, link,
				admodel.InternalPortableReplicationReply{Kind: link, Status: 8453}),
		}, nil
	})
	config := admodel.Config{
		Endpoint: admodel.Endpoint{Host: "dc.example.test"}, Backend: admodel.BackendPortable,
		Authentication: admodel.AuthenticationKerberos, Kerberos: &admodel.KerberosCredentials{
			Source: admodel.KerberosPassword, Username: "reader", Realm: "EXAMPLE.TEST", SPN: "ldap/dc.example.test", Password: []byte("owned-unit-fixture"),
		},
	}
	got, err := adengine.InternalReadReplicationFailures(context.Background(), config, admodel.ReplicationFailureQuery{}, reader)
	var status *admodel.NativeStatusError
	if len(got.Servers) != 1 || got.Complete || !errors.As(err, &status) || status.Code != 8453 {
		t.Fatalf("portable partial categories lost: %v", err)
	}
	server := got.Servers[0]
	if !server.Connections.Available || !server.Connections.Complete || server.Links.Available || server.Links.Complete ||
		!errors.Is(err, admodel.ErrIncompleteResult) || len(server.Failures) != 0 {
		t.Fatal("refused category replaced a confirmed empty sibling or became healthy")
	}
}

func TestReplicationMissingRPCCategoryIsIncompleteWithoutBorrowingSiblingStatus(t *testing.T) {
	for _, deniedSibling := range []bool{false, true} {
		reader := InternalReplicationTestReader(func(
			context.Context, admodel.Config, admodel.RootDSE, []byte, admodel.InternalReplicationRequest,
		) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
			if deniedSibling {
				return map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply{
					admodel.InternalReplicationLinkFailures: {InternalErr: &admodel.NativeStatusError{Operation: "IDL_DRSGetReplInfo", Code: 8453}},
				}, nil
			}
			return map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply{
				admodel.InternalReplicationConnectFailures: {},
			}, nil
		})
		got, err := adengine.InternalReadReplicationFailures(context.Background(),
			admodel.Config{Endpoint: admodel.Endpoint{Host: "dc.example.test"}}, admodel.ReplicationFailureQuery{}, reader)
		if len(got.Servers) != 1 || got.Complete || got.Servers[0].Observation.Complete || !errors.Is(err, admodel.ErrIncompleteResult) {
			t.Fatalf("missing category became complete: deniedSibling=%v complete=%v err=%v", deniedSibling, got.Complete, err)
		}
		missing := got.Servers[0].Links
		if deniedSibling {
			missing = got.Servers[0].Connections
		}
		var borrowed *admodel.NativeStatusError
		if !missing.Requested || missing.Available || missing.Complete || !errors.Is(missing.Error, admodel.ErrIncompleteResult) ||
			errors.As(missing.Error, &borrowed) {
			t.Fatalf("missing category borrowed another category's status: %v", missing.Error)
		}
	}
}

func TestPortableReplicationOutboundSurvivesClosedRPCGate(t *testing.T) {
	for _, direction := range []admodel.ReplicationDirection{admodel.ReplicationOutbound, admodel.ReplicationBoth} {
		reader := InternalReplicationTestReader(adengine.InternalReadReplicationBackend)
		reader.InternalDial = func(_ context.Context, config admodel.Config) (*adengine.Client, error) {
			return adengine.InternalNewClient(config, InternalTestSession{
				InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
					return map[string][][]byte{"supportedcapabilities": {[]byte(admodel.CapabilityActiveDirectory)}}, nil
				},
				InternalRanged: func(context.Context, string, []string) (map[string][][]byte, error) {
					return map[string][][]byte{"msds-replalloutboundneighbors": {[]byte(InternalOutboundXML)}}, nil
				},
				InternalFinish: func() error { return nil },
			}), nil
		}
		config := admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc.example.test"}, Backend: admodel.BackendPortable,
			Authentication: admodel.AuthenticationKerberos, Kerberos: &admodel.KerberosCredentials{
				Source: admodel.KerberosPassword, Username: "reader", Realm: "EXAMPLE.TEST", SPN: "ldap/dc.example.test", Password: []byte("owned-unit-fixture"),
			},
		}
		got, err := adengine.InternalReadReplicationPartners(context.Background(), config,
			admodel.ReplicationPartnerQuery{Direction: direction}, reader)
		if len(got.Servers) != 1 || len(got.Servers[0].Partners) != 1 || !got.Servers[0].Outbound.Complete ||
			got.Servers[0].Partners[0].Direction != admodel.ReplicationOutbound {
			t.Fatalf("outbound LDAP observation lost: %v", err)
		}
		if direction == admodel.ReplicationOutbound {
			if err != nil || !got.Complete || got.Servers[0].Inbound.Requested {
				t.Fatal("outbound-only query unexpectedly required RPC")
			}
		} else if !errors.Is(err, admodel.ErrBackendUnavailable) || got.Complete || !got.Servers[0].Inbound.Requested || got.Servers[0].Inbound.Available {
			t.Fatal("closed RPC category became healthy or hid the usable outbound observation")
		}
	}
}
