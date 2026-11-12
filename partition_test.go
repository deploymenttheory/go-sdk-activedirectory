package activedirectory

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestPartitionSelectionAndServerResolution(t *testing.T) {
	for _, explicit := range []string{"", `cn=App\2cOne,dc=example,dc=test`} {
		t.Run(explicit, func(t *testing.T) {
			const canonical = `CN=App\,One,DC=example,DC=test`
			var bases []string
			client := newClient(Config{Partition: explicit, Timeout: time.Second}, testSession{
				base: func(_ context.Context, base string, properties []string) (map[string][][]byte, error) {
					bases = append(bases, base)
					if base == "" {
						if !reflect.DeepEqual(properties, []string{"defaultNamingContext"}) {
							t.Fatalf("unexpected discovery projection: %v", properties)
						}
						return map[string][][]byte{"defaultnamingcontext": {[]byte(canonical)}}, nil
					}
					return map[string][][]byte{"distinguishedname": {[]byte(canonical)}, "instancetype": {[]byte("5")}}, nil
				},
				finish: func() error { return nil },
			})
			defer client.Close()
			partition, err := client.Partition(context.Background())
			wantBases := []string{"", canonical}
			if explicit != "" {
				wantBases = []string{explicit}
			}
			if err != nil || partition.DistinguishedName != canonical || partition.InstanceType != 5 || !reflect.DeepEqual(bases, wantBases) {
				t.Fatalf("partition=%+v reads=%q err=%v", partition, bases, err)
			}
		})
	}
}

func TestPartitionFailureDoesNotSelectAnotherContext(t *testing.T) {
	missing := &LDAPError{Operation: "base", Code: 32, MatchedDN: "DC=example,DC=test"}
	denied := &LDAPError{Operation: "base", Code: 50}
	referral := &LDAPError{Operation: "base", Code: 10}
	for _, tc := range []struct {
		name       string
		explicit   string
		attributes map[string][][]byte
		readErr    error
		wantErr    error
	}{
		{"no-default", "", map[string][][]byte{"namingcontexts": {[]byte("CN=Configuration"), []byte("CN=Schema")}}, nil, ErrNoDefaultPartition},
		{"empty-default", "", map[string][][]byte{"defaultnamingcontext": {[]byte("")}}, nil, ErrNoDefaultPartition},
		{"malformed-default", "", map[string][][]byte{"defaultnamingcontext": {[]byte("one"), []byte("two")}}, nil, ErrInvalidResult},
		{"discovery-denied", "", map[string][][]byte{"defaultnamingcontext": {[]byte("CN=App")}}, denied, denied},
		{"missing", "CN=Missing", nil, missing, missing},
		{"denied", "CN=App", nil, denied, denied},
		{"referral", "CN=Remote", nil, referral, referral},
		{"subtree", "CN=Child,CN=App", map[string][][]byte{"distinguishedname": {[]byte("CN=Child,CN=App")}, "instancetype": {[]byte("4")}}, nil, ErrNotNamingContext},
		{"missing-marker", "CN=App", map[string][][]byte{"distinguishedname": {[]byte("CN=App")}}, nil, ErrInvalidResult},
		{"missing-dn", "CN=App", map[string][][]byte{"instancetype": {[]byte("5")}}, nil, ErrInvalidResult},
		{"malformed-marker", "CN=App", map[string][][]byte{"distinguishedname": {[]byte("CN=App")}, "instancetype": {[]byte("not-an-integer")}}, nil, ErrInvalidResult},
		{"partial-denied", "CN=App", map[string][][]byte{"distinguishedname": {[]byte("CN=App")}, "instancetype": {[]byte("5")}}, denied, denied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := newClient(Config{Partition: tc.explicit, Timeout: time.Second}, testSession{
				base: func(_ context.Context, base string, _ []string) (map[string][][]byte, error) {
					calls++
					if base != tc.explicit {
						t.Fatalf("substituted base: %q", base)
					}
					return tc.attributes, tc.readErr
				},
				finish: func() error { return nil },
			})
			defer client.Close()
			result, err := client.Partition(context.Background())
			if !errors.Is(err, tc.wantErr) || calls != 1 {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
			if tc.name == "partial-denied" && result.DistinguishedName != "CN=App" {
				t.Fatal("lost partial partition")
			}
		})
	}
}

func TestPartitionCancellationBetweenDiscoveryAndValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	client := newClient(Config{Timeout: time.Second}, testSession{
		base: func(context.Context, string, []string) (map[string][][]byte, error) {
			calls++
			cancel()
			return map[string][][]byte{"defaultnamingcontext": {[]byte("CN=App")}}, nil
		},
		finish: func() error { return nil },
	})
	defer client.Close()
	if _, err := client.Partition(ctx); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled discovery: calls=%d, %v", calls, err)
	}
}

func TestCloseCancelsPartitionReadBeforeUnbinding(t *testing.T) {
	started := make(chan struct{})
	stopped := false
	client := newClient(Config{Partition: "CN=App", Timeout: time.Minute}, testSession{
		base: func(ctx context.Context, _ string, _ []string) (map[string][][]byte, error) {
			close(started)
			<-ctx.Done()
			stopped = true
			return map[string][][]byte{"distinguishedname": {[]byte("CN=App")}}, context.Cause(ctx)
		},
		finish: func() error {
			if !stopped {
				t.Error("unbind preceded read completion")
			}
			return nil
		},
	})
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
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Fatalf("active partition read: %v", err)
	}
	if _, err := client.Partition(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("partition after close: %v", err)
	}
}
