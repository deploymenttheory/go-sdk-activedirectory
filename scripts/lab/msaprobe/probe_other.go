//go:build !windows || (!amd64 && !arm64)

package main

// The managed-account APIs exist only on supported Windows builds. The probe
// still compiles elsewhere so the lab tree builds on any CI platform; it
// reports the operation as unavailable rather than pretending to a reading.
func probe(account string) reading {
	return reading{
		Account:     account,
		Unsupported: []string{"native managed account APIs require Windows amd64 or arm64"},
	}
}
