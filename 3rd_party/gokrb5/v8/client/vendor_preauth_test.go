package client

import (
	"math"
	"strconv"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
)

func TestVendorPreauthConfigurationBounds(t *testing.T) {
	cases := [][]int{nil}
	if strconv.IntSize == 64 {
		tooLarge := int64(math.MaxInt32) + 1
		tooSmall := int64(math.MinInt32) - 1
		cases = append(cases, []int{int(tooLarge)}, []int{int(tooSmall)})
	}
	for _, preferred := range cases {
		cfg := config.New()
		cfg.LibDefaults.PreferredPreauthTypes = preferred
		cl := &Client{Config: cfg, settings: NewSettings(AssumePreAuthentication(true))}
		if err := setPAData(cl, nil, &messages.ASReq{}); err == nil {
			t.Fatalf("invalid preferred etype accepted: %v", preferred)
		}
	}
}
