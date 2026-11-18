package messages

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/errorcode"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func TestVendorWrappedReplyErrorRetainsKDCClassification(t *testing.T) {
	kdc := NewKRBError(types.PrincipalName{}, "EXAMPLE.COM", errorcode.KDC_ERR_PREAUTH_REQUIRED, "pre-authentication required")
	wire, err := kdc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cause := fmt.Errorf("decoding reply: %w", asn1.StructuralError{Msg: "unexpected application tag"})
	err = processUnmarshalReplyError(wire, cause)
	var got KRBError
	if !errors.As(err, &got) || got.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Fatalf("lost wrapped structural error classification: %v", err)
	}
}

func TestVendorMalformedReplyRetainsParseCause(t *testing.T) {
	cause := fmt.Errorf("decoding reply: %w", asn1.StructuralError{Msg: "truncated application tag"})
	err := processUnmarshalReplyError([]byte{0x7e}, cause)
	if !errors.Is(err, cause) {
		t.Fatalf("lost original parse failure: %v", err)
	}
}
