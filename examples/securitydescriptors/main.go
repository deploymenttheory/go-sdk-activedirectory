// This offline example edits owned descriptor bytes; it makes no directory call.
package main

import (
	"fmt"
	"log"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func main() {
	original, err := conditions.ParseSDDL("O:SYG:BAD:PAI(A;;RP;;;SY)S:(AU;SA;RP;;;SY)")
	if err != nil {
		log.Fatal(err)
	}
	conditional, err := conditions.Compile(conditions.ACE{
		TrusteeSID: "S-1-1-0", AccessMask: 0x100,
		Condition: conditions.Compare(conditions.Claim{Scope: conditions.User, Name: "Department"}, conditions.Equal, conditions.Text("Finance")),
	})
	if err != nil {
		log.Fatal(err)
	}
	grant, err := conditions.ParseSDDL(conditional)
	if err != nil {
		log.Fatal(err)
	}
	acl := original.DACL()
	acl.ACEs = append(acl.ACEs, grant.DACL().ACEs...)
	edited, err := original.WithDACL(acl)
	if err != nil {
		log.Fatal(err)
	}
	text, err := edited.SDDL()
	if err != nil {
		log.Fatal(err)
	}
	raw, err := edited.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(text)
	fmt.Printf(
		"binary_bytes=%d original_dacl_aces=%d edited_dacl_aces=%d retained_sacl_aces=%d\n",
		len(raw),
		len(original.DACL().ACEs),
		len(edited.DACL().ACEs),
		len(edited.SACL().ACEs),
	)
}
