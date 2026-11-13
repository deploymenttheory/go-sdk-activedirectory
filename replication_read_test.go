package activedirectory

import (
	"context"
	"errors"
	"testing"
	"time"
)

func replicationTestReader(native func(context.Context, Config, RootDSE, []byte, replicationRequest) (map[replicationInfo]replicationNativeReply, error)) replicationReader {
	return replicationReader{dial: func(_ context.Context, config Config) (*Client, error) {
		return newClient(config, testSession{read: func(context.Context, []string) (map[string][][]byte, error) {
			return map[string][][]byte{"supportedcapabilities": {[]byte(CapabilityActiveDirectory)}}, nil
		}, finish: func() error { return nil }}), nil
	}, native: native}
}

func TestReplicationFailuresPreserveSuccessfulServersAndCategories(t *testing.T) {
	denied := &NativeStatusError{Operation: "DsReplicaGetInfo2W", Code: 8453}
	reader := replicationTestReader(func(_ context.Context, config Config, _ RootDSE, _ []byte, _ replicationRequest) (map[replicationInfo]replicationNativeReply, error) {
		if config.Endpoint.Host == "good.example.test" {
			return map[replicationInfo]replicationNativeReply{replicationConnectFailures: {}, replicationLinkFailures: {}}, nil
		}
		return map[replicationInfo]replicationNativeReply{replicationConnectFailures: {data: replicationNativeData{failures: []ReplicationFailure{{Kind: ReplicationConnectionFailure, LastResult: 1722, LastResultAvailable: true}}}}, replicationLinkFailures: {err: denied}}, nil
	})
	got, err := readReplicationFailures(context.Background(), Config{Endpoint: Endpoint{Host: "good.example.test"}}, ReplicationFailureQuery{Selection: ReplicationSelection{Servers: []Endpoint{{Host: "bad.example.test"}, {Host: "good.example.test"}}}}, reader)
	if !errors.Is(err, denied) || got.Complete || !got.Targets.Complete || len(got.Servers) != 2 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	if !got.Servers[1].Observation.Complete || len(got.Servers[1].Failures) != 0 || !got.Servers[1].Links.Available || !got.Servers[1].Connections.Complete {
		t.Fatal("confirmed empty success lost")
	}
	bad := got.Servers[0]
	if bad.Observation.Complete || len(bad.Failures) != 1 || !bad.Connections.Complete || bad.Links.Available || !errors.Is(bad.Links.Error, denied) {
		t.Fatalf("partial categories lost: %+v", bad)
	}
}

func TestReplicationPartialNativeDataRemainsAvailable(t *testing.T) {
	reader := replicationTestReader(func(context.Context, Config, RootDSE, []byte, replicationRequest) (map[replicationInfo]replicationNativeReply, error) {
		return map[replicationInfo]replicationNativeReply{replicationPendingOperations: {data: replicationNativeData{operations: []ReplicationQueueOperation{{SerialNumber: 9, Type: 99}}}, err: ErrInvalidNativeResult}}, nil
	})
	got, err := readReplicationQueue(context.Background(), Config{Endpoint: Endpoint{Host: "dc.example.test"}}, ReplicationQueueQuery{}, reader)
	if err == nil || got.Complete || len(got.Servers) != 1 || len(got.Servers[0].Operations) != 1 || !got.Servers[0].State.Available || got.Servers[0].State.Complete {
		t.Fatalf("partial data available state: %+v err=%v", got, err)
	}
}

func TestReplicationEarlyAndCleanupFailuresAreNotHealthyEmpty(t *testing.T) {
	for _, mode := range []string{"dial", "root", "bind", "close", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("injected failure")
			reader := replicationTestReader(func(context.Context, Config, RootDSE, []byte, replicationRequest) (map[replicationInfo]replicationNativeReply, error) {
				if mode == "bind" {
					return nil, sentinel
				}
				return map[replicationInfo]replicationNativeReply{replicationPendingOperations: {}}, nil
			})
			reader.dial = func(_ context.Context, config Config) (*Client, error) {
				if mode == "dial" {
					return nil, sentinel
				}
				return newClient(config, testSession{read: func(context.Context, []string) (map[string][][]byte, error) {
					if mode == "root" {
						return nil, sentinel
					}
					if mode == "cancelled" {
						cancel()
						return nil, context.Canceled
					}
					return map[string][][]byte{"supportedcapabilities": {[]byte(CapabilityActiveDirectory)}}, nil
				}, finish: func() error {
					if mode == "close" {
						return sentinel
					}
					return nil
				}}), nil
			}
			got, err := readReplicationQueue(ctx, Config{Endpoint: Endpoint{Host: "dc.example.test"}, Timeout: time.Second}, ReplicationQueueQuery{}, reader)
			if err == nil || got.Complete || len(got.Servers) != 1 || got.Servers[0].Observation.Complete {
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
				values[attribute+";range=0-0"] = [][]byte{[]byte(outboundXML)}
			case "malformed":
				values[attribute] = [][]byte{[]byte("<invalid/>")}
			case "good":
				values[attribute] = [][]byte{[]byte(outboundXML)}
			}
			reader := replicationTestReader(nil)
			reader.dial = func(_ context.Context, config Config) (*Client, error) {
				return newClient(config, testSession{read: func(context.Context, []string) (map[string][][]byte, error) {
					return map[string][][]byte{"supportedcapabilities": {[]byte(CapabilityActiveDirectory)}}, nil
				}, ranged: func(context.Context, string, []string) (map[string][][]byte, error) { return values, nil }, finish: func() error { return nil }}), nil
			}
			got, err := readReplicationPartners(context.Background(), Config{Endpoint: Endpoint{Host: "dc.example.test"}}, ReplicationPartnerQuery{Direction: ReplicationOutbound}, reader)
			if (err == nil) != (mode == "good") || got.Complete != (mode == "good") || len(got.Servers) != 1 {
				t.Fatalf("mode=%s result=%+v err=%v", mode, got, err)
			}
			server := got.Servers[0]
			if server.Inbound.Requested || !server.Outbound.Requested || len(server.OutboundObjects) < 1 {
				t.Fatalf("wrong requested/raw state: %+v", server)
			}
			if mode == "range" && (len(server.Partners) != 1 || !server.Outbound.Available || server.Outbound.Complete) {
				t.Fatal("ranged values silently discarded or declared complete")
			}
		})
	}
}
