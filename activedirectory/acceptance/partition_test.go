package acceptance

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPartitionSelectionAndServerResolution(t *testing.T) {
	for _, explicit := range []string{"", `cn=App\2cOne,dc=example,dc=test`} {
		t.Run(explicit, func(t *testing.T) {
			const canonical = `CN=App\,One,DC=example,DC=test`
			var bases []string
			client := adengine.InternalNewClient(
				admodel.Config{Partition: explicit, Timeout: time.Second},
				InternalTestSession{
					InternalBase: func(_ context.Context, base string, properties []string) (map[string][][]byte, error) {
						bases = append(bases, base)
						if base == "" {
							if !reflect.DeepEqual(properties, []string{"defaultNamingContext"}) {
								t.Fatalf("unexpected discovery projection: %v", properties)
							}
							return map[string][][]byte{
								"defaultnamingcontext": {[]byte(canonical)},
							}, nil
						}
						return map[string][][]byte{
							"distinguishedname": {[]byte(canonical)},
							"instancetype":      {[]byte("5")},
						}, nil
					},
					InternalFinish: func() error { return nil },
				},
			)
			defer client.Close()
			partition, err := client.Partition(context.Background())
			wantBases := []string{"", canonical}
			if explicit != "" {
				wantBases = []string{explicit}
			}
			if err != nil || partition.DistinguishedName != canonical ||
				partition.InstanceType != 5 ||
				!reflect.DeepEqual(bases, wantBases) {
				t.Fatalf("partition=%+v reads=%q err=%v", partition, bases, err)
			}
		})
	}
}

func TestPartitionFailureDoesNotSelectAnotherContext(t *testing.T) {
	missing := &admodel.LDAPError{Operation: "base", Code: 32, MatchedDN: "DC=example,DC=test"}
	denied := &admodel.LDAPError{Operation: "base", Code: 50}
	referral := &admodel.LDAPError{Operation: "base", Code: 10}
	for _, tc := range []struct {
		InternalName       string
		InternalExplicit   string
		InternalAttributes map[string][][]byte
		InternalReadErr    error
		InternalWantErr    error
	}{
		{"no-default", "", map[string][][]byte{"namingcontexts": {[]byte("CN=Configuration"), []byte("CN=Schema")}}, nil, admodel.ErrNoDefaultPartition},
		{"empty-default", "", map[string][][]byte{"defaultnamingcontext": {[]byte("")}}, nil, admodel.ErrNoDefaultPartition},
		{"malformed-default", "", map[string][][]byte{"defaultnamingcontext": {[]byte("one"), []byte("two")}}, nil, admodel.ErrInvalidResult},
		{"discovery-denied", "", map[string][][]byte{"defaultnamingcontext": {[]byte("CN=App")}}, denied, denied},
		{"missing", "CN=Missing", nil, missing, missing},
		{"denied", "CN=App", nil, denied, denied},
		{"referral", "CN=Remote", nil, referral, referral},
		{"subtree", "CN=Child,CN=App", map[string][][]byte{"distinguishedname": {[]byte("CN=Child,CN=App")}, "instancetype": {[]byte("4")}}, nil, admodel.ErrNotNamingContext},
		{"missing-marker", "CN=App", map[string][][]byte{"distinguishedname": {[]byte("CN=App")}}, nil, admodel.ErrInvalidResult},
		{"missing-dn", "CN=App", map[string][][]byte{"instancetype": {[]byte("5")}}, nil, admodel.ErrInvalidResult},
		{"malformed-marker", "CN=App", map[string][][]byte{"distinguishedname": {[]byte("CN=App")}, "instancetype": {[]byte("not-an-integer")}}, nil, admodel.ErrInvalidResult},
		{"partial-denied", "CN=App", map[string][][]byte{"distinguishedname": {[]byte("CN=App")}, "instancetype": {[]byte("5")}}, denied, denied},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			calls := 0
			client := adengine.InternalNewClient(
				admodel.Config{Partition: tc.InternalExplicit, Timeout: time.Second},
				InternalTestSession{
					InternalBase: func(_ context.Context, base string, _ []string) (map[string][][]byte, error) {
						calls++
						if base != tc.InternalExplicit {
							t.Fatalf("substituted base: %q", base)
						}
						return tc.InternalAttributes, tc.InternalReadErr
					},
					InternalFinish: func() error { return nil },
				},
			)
			defer client.Close()
			result, err := client.Partition(context.Background())
			if !errors.Is(err, tc.InternalWantErr) || calls != 1 {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
			if tc.InternalName == "partial-denied" && result.DistinguishedName != "CN=App" {
				t.Fatal("lost partial partition")
			}
		})
	}
}

func TestPartitionCancellationBetweenDiscoveryAndValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	client := adengine.InternalNewClient(admodel.Config{Timeout: time.Second}, InternalTestSession{
		InternalBase: func(context.Context, string, []string) (map[string][][]byte, error) {
			calls++
			cancel()
			return map[string][][]byte{"defaultnamingcontext": {[]byte("CN=App")}}, nil
		},
		InternalFinish: func() error { return nil },
	})
	defer client.Close()
	if _, err := client.Partition(ctx); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled discovery: calls=%d, %v", calls, err)
	}
}

func TestCloseCancelsPartitionReadBeforeUnbinding(t *testing.T) {
	started := make(chan struct{})
	stopped := false
	client := adengine.InternalNewClient(
		admodel.Config{Partition: "CN=App", Timeout: time.Minute},
		InternalTestSession{
			InternalBase: func(ctx context.Context, _ string, _ []string) (map[string][][]byte, error) {
				close(started)
				<-ctx.Done()
				stopped = true
				return map[string][][]byte{
						"distinguishedname": {[]byte("CN=App")},
					}, context.Cause(
						ctx,
					)
			},
			InternalFinish: func() error {
				if !stopped {
					t.Error("unbind preceded read completion")
				}
				return nil
			},
		},
	)
	done := make(chan error, 1)
	go func() { _, err := client.Partition(context.Background()); done <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("read did not start")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, admodel.ErrClosed) {
		t.Fatalf("active partition read: %v", err)
	}
	if _, err := client.Partition(context.Background()); !errors.Is(err, admodel.ErrClosed) {
		t.Fatalf("partition after close: %v", err)
	}
}
