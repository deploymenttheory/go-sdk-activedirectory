package activedirectory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReplicationOutboundContinuesRangesOnOneSession(t *testing.T) {
	const attr = "msds-replalloutboundneighbors"
	for _, mode := range []string{"complete", "gap", "short", "changed", "failed", "empty-terminal"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			sentinel := &LDAPError{Operation: "range read", Code: 50}
			client := newClient(Config{Timeout: time.Second}, testSession{ranged: func(_ context.Context, base string, properties []string) (map[string][][]byte, error) {
				calls++
				if base != "" {
					t.Fatalf("base=%s", base)
				}
				if calls == 1 {
					if !strings.EqualFold(properties[0], attr) {
						t.Fatalf("first request=%v", properties)
					}
					if mode == "short" {
						return map[string][][]byte{attr + ";range=0-1": {[]byte(outboundXML)}}, nil
					}
					return map[string][][]byte{attr: nil, attr + ";range=0-0": {[]byte(outboundXML)}}, nil
				}
				if calls != 2 || !strings.EqualFold(properties[0], attr+";range=1-*") {
					t.Fatalf("continuation=%v calls=%d", properties, calls)
				}
				switch mode {
				case "gap":
					return map[string][][]byte{attr + ";range=2-*": {[]byte(outboundXML)}}, nil
				case "changed":
					return map[string][][]byte{attr: {[]byte(outboundXML)}}, nil
				case "failed":
					return nil, sentinel
				case "empty-terminal":
					return map[string][][]byte{attr + ";range=1-*": nil}, nil
				}
				return map[string][][]byte{attr + ";range=1-*": {[]byte(outboundXML)}}, nil
			}, search: func(context.Context, SearchOptions) (searchCursor, error) { return nil, ErrUnsupported }, finish: func() error { return nil }})
			defer client.Close()
			partners, objects, err := readReplicationOutbound(context.Background(), client, "")
			if mode == "complete" {
				if err != nil || len(partners) != 2 || len(objects) != 2 || calls != 2 {
					t.Fatalf("range completion rows=%d objects=%d calls=%d err=%v", len(partners), len(objects), calls, err)
				}
			} else {
				if err == nil || len(partners) == 0 {
					t.Fatalf("range uncertainty lost: rows=%d err=%v", len(partners), err)
				}
				if mode == "failed" && !errors.Is(err, sentinel) {
					t.Fatalf("native error masked: %v", err)
				}
			}
		})
	}
}
