package types_test

import (
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func TestAuthenticatorFactoryDoesNotReuseReplayTimestamps(t *testing.T) {
	seen := make(map[int64]bool)
	start := time.Now()
	for i := 0; i < 4096; i++ {
		auth, err := types.NewAuthenticator("EXAMPLE.TEST", types.NewPrincipalName(1, "owned-fixture"))
		if err != nil {
			t.Fatal(err)
		}
		stamp := auth.CTime.Truncate(time.Second).UnixMicro() + int64(auth.Cusec)
		if seen[stamp] {
			t.Fatal("independent real authenticators reused a replay-cache timestamp")
		}
		seen[stamp] = true
		if auth.Cusec < 0 || auth.Cusec >= 1000000 || time.UnixMicro(stamp).Before(start.Add(-time.Second)) || time.UnixMicro(stamp).After(time.Now().Add(time.Second)) {
			t.Fatal("authenticator timestamp escaped the bounded wall-clock window")
		}
	}
}
