package credentials

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/test/testdata"
)

func TestSDKCCacheBoundedDecodingAndAtomicFailure(t *testing.T) {
	valid, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(valid); i++ {
		c := CCache{Path: "retained", Version: 99}
		if err := c.Unmarshal(valid[:i]); err != nil && (c.Version != 99 || c.Path != "retained" || len(c.Credentials) != 0) {
			t.Fatalf("partial parse installed at prefix %d", i)
		}
	}
	for _, b := range [][]byte{nil, {5}, {5, 4, 255, 255}, {5, 4, 0, 0, 0, 0, 0, 1, 255, 255, 255, 255}} {
		var c CCache
		if err := c.Unmarshal(b); err == nil {
			t.Fatalf("accepted malformed cache %x", b)
		}
	}
	var c CCache
	if err := c.Unmarshal(valid); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), valid...)
	valid[0] = 0
	if bytes.Equal(before, valid) {
		t.Fatal("test did not mutate source")
	}
	if c.Version != 4 || len(c.Credentials) != 3 {
		t.Fatal("valid fixture was not decoded")
	}
}

func FuzzSDKCCacheBounds(f *testing.F) {
	b, _ := hex.DecodeString(testdata.CCACHE_TEST)
	f.Add(b)
	f.Add([]byte{5, 4, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		var c CCache
		_ = c.Unmarshal(b)
	})
}
