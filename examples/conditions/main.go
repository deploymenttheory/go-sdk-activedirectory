package main

import (
	"fmt"
	"log"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func main() {
	expression := conditions.All(
		conditions.Compare(conditions.Claim{Scope: conditions.User, Name: "Department"}, conditions.Equal, conditions.Text("Finance")),
		conditions.MemberOf(false, "S-1-5-32-544"),
	)
	sddl, err := conditions.Compile(conditions.ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: expression})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sddl)
}
