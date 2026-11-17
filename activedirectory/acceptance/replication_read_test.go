package acceptance

import (
	"context"
	"errors"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalReplicationTestReader(
	native func(context.Context, admodel.Config, admodel.RootDSE, []byte, admodel.InternalReplicationRequest) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error),
) adengine.InternalReplicationReader {
	return adengine.InternalReplicationReader{
		InternalDial: func(_ context.Context, config admodel.Config) (*adengine.Client, error) {
			return adengine.InternalNewClient(
				config,
				InternalTestSession{
					InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
						return map[string][][]byte{
							"supportedcapabilities": {[]byte(admodel.CapabilityActiveDirectory)},
						}, nil
					},
					InternalFinish: func() error { return nil },
				},
			), nil
		},
		InternalNative: native,
	}
}

func TestReplicationFailuresPreserveSuccessfulServersAndCategories(t *testing.T) {
	denied := &admodel.NativeStatusError{Operation: "DsReplicaGetInfo2W", Code: 8453}
	reader := InternalReplicationTestReader(
		func(_ context.Context, config admodel.Config, _ admodel.RootDSE, _ []byte, _ admodel.InternalReplicationRequest) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
			if config.Endpoint.Host == "good.example.test" {
				return map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply{
					admodel.InternalReplicationConnectFailures: {},
					admodel.InternalReplicationLinkFailures:    {},
				}, nil
			}
			return map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply{
				admodel.InternalReplicationConnectFailures: {
					InternalData: admodel.InternalReplicationNativeData{
						InternalFailures: []admodel.ReplicationFailure{
							{
								Kind:                admodel.ReplicationConnectionFailure,
								LastResult:          1722,
								LastResultAvailable: true,
							},
						},
					},
				},
				admodel.InternalReplicationLinkFailures: {InternalErr: denied},
			}, nil
		},
	)
	got, err := adengine.InternalReadReplicationFailures(
		context.Background(),
		admodel.Config{Endpoint: admodel.Endpoint{Host: "good.example.test"}},
		admodel.ReplicationFailureQuery{
			Selection: admodel.ReplicationSelection{
				Servers: []admodel.Endpoint{
					{Host: "bad.example.test"},
					{Host: "good.example.test"},
				},
			},
		},
		reader,
	)
	if !errors.Is(err, denied) || got.Complete || !got.Targets.Complete || len(got.Servers) != 2 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	if !got.Servers[1].Observation.Complete || len(got.Servers[1].Failures) != 0 ||
		!got.Servers[1].Links.Available ||
		!got.Servers[1].Connections.Complete {
		t.Fatal("confirmed empty success lost")
	}
	bad := got.Servers[0]
	if bad.Observation.Complete || len(bad.Failures) != 1 || !bad.Connections.Complete ||
		bad.Links.Available ||
		!errors.Is(bad.Links.Error, denied) {
		t.Fatalf("partial categories lost: %+v", bad)
	}
}

func TestReplicationPartialNativeDataRemainsAvailable(t *testing.T) {
	reader := InternalReplicationTestReader(
		func(context.Context, admodel.Config, admodel.RootDSE, []byte, admodel.InternalReplicationRequest) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
			return map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply{
				admodel.InternalReplicationPendingOperations: {
					InternalData: admodel.InternalReplicationNativeData{
						InternalOperations: []admodel.ReplicationQueueOperation{
							{SerialNumber: 9, Type: 99},
						},
					},
					InternalErr: admodel.ErrInvalidNativeResult,
				},
			}, nil
		},
	)
	got, err := adengine.InternalReadReplicationQueue(
		context.Background(),
		admodel.Config{Endpoint: admodel.Endpoint{Host: "dc.example.test"}},
		admodel.ReplicationQueueQuery{},
		reader,
	)
	if err == nil || got.Complete || len(got.Servers) != 1 || len(got.Servers[0].Operations) != 1 ||
		!got.Servers[0].State.Available ||
		got.Servers[0].State.Complete {
		t.Fatalf("partial data available state: %+v err=%v", got, err)
	}
}

func TestReplicationEarlyAndCleanupFailuresAreNotHealthyEmpty(t *testing.T) {
	for _, mode := range []string{"dial", "root", "bind", "close", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("injected failure")
			reader := InternalReplicationTestReader(
				func(context.Context, admodel.Config, admodel.RootDSE, []byte, admodel.InternalReplicationRequest) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
					if mode == "bind" {
						return nil, sentinel
					}
					return map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply{
						admodel.InternalReplicationPendingOperations: {},
					}, nil
				},
			)
			reader.InternalDial = func(_ context.Context, config admodel.Config) (*adengine.Client, error) {
				if mode == "dial" {
					return nil, sentinel
				}
				return adengine.InternalNewClient(
					config,
					InternalTestSession{
						InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
							if mode == "root" {
								return nil, sentinel
							}
							if mode == "cancelled" {
								cancel()
								return nil, context.Canceled
							}
							return map[string][][]byte{
								"supportedcapabilities": {
									[]byte(admodel.CapabilityActiveDirectory),
								},
							}, nil
						},
						InternalFinish: func() error {
							if mode == "close" {
								return sentinel
							}
							return nil
						},
					},
				), nil
			}
			got, err := adengine.InternalReadReplicationQueue(
				ctx,
				admodel.Config{
					Endpoint: admodel.Endpoint{Host: "dc.example.test"},
					Timeout:  time.Second,
				},
				admodel.ReplicationQueueQuery{},
				reader,
			)
			if err == nil || got.Complete || len(got.Servers) != 1 ||
				got.Servers[0].Observation.Complete {
				t.Fatalf("failure became healthy: %+v %v", got, err)
			}
			if mode != "close" && got.Servers[0].State.Complete {
				t.Fatalf("unperformed read complete: %+v", got)
			}
		})
	}
}

func TestReplicationOutboundOmissionAndRangeRetainUncertainty(t *testing.T) {
	for _, mode := range []string{"omitted", "empty", "range", "malformed", "good"} {
		t.Run(mode, func(t *testing.T) {
			attribute := "msds-replalloutboundneighbors"
			values := map[string][][]byte{}
			switch mode {
			case "empty":
				values[attribute] = nil
			case "range":
				values[attribute] = nil
				values[attribute+";range=0-0"] = [][]byte{[]byte(InternalOutboundXML)}
			case "malformed":
				values[attribute] = [][]byte{[]byte("<invalid/>")}
			case "good":
				values[attribute] = [][]byte{[]byte(InternalOutboundXML)}
			}
			reader := InternalReplicationTestReader(nil)
			reader.InternalDial = func(_ context.Context, config admodel.Config) (*adengine.Client, error) {
				return adengine.InternalNewClient(
					config,
					InternalTestSession{
						InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
							return map[string][][]byte{
								"supportedcapabilities": {
									[]byte(admodel.CapabilityActiveDirectory),
								},
							}, nil
						},
						InternalRanged: func(context.Context, string, []string) (map[string][][]byte, error) { return values, nil },
						InternalFinish: func() error { return nil },
					},
				), nil
			}
			got, err := adengine.InternalReadReplicationPartners(
				context.Background(),
				admodel.Config{Endpoint: admodel.Endpoint{Host: "dc.example.test"}},
				admodel.ReplicationPartnerQuery{Direction: admodel.ReplicationOutbound},
				reader,
			)
			if (err == nil) != (mode == "good") || got.Complete != (mode == "good") ||
				len(got.Servers) != 1 {
				t.Fatalf("mode=%s result=%+v err=%v", mode, got, err)
			}
			server := got.Servers[0]
			if server.Inbound.Requested || !server.Outbound.Requested ||
				len(server.OutboundObjects) < 1 {
				t.Fatalf("wrong requested/raw state: %+v", server)
			}
			if mode == "range" &&
				(len(server.Partners) != 1 || !server.Outbound.Available || server.Outbound.Complete) {
				t.Fatal("ranged values silently discarded or declared complete")
			}
		})
	}
}
