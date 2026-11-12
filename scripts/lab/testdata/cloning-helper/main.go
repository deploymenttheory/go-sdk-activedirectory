// Test-only child for reference-cloning.ps1; never contacts Windows or AD APIs.
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	switch os.Getenv("ADSDK_HARNESS_TEST_MODE") {
	case "timeout":
		time.Sleep(time.Minute)
	case "invalid":
		fmt.Println("not json")
	case "failure":
		fmt.Fprintln(os.Stderr, "owned test failure")
		os.Exit(7)
	case "empty":
		fmt.Println(`{"entries":[],"complete":true,"authorization_limited":true}`)
	default:
		fmt.Println(`{"entries":[{"name":"Fixture","type":"Service"}],"complete":true,"authorization_limited":true}`)
	}
}
