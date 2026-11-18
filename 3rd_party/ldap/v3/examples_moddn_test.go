package ldap

import (
	"log"
)

// This example shows how to rename an entry without moving it
func ExampleConn_ModifyDN_renameNoMove() {
	input := exampleReadCredentials()
	conn, err := exampleDialTLS()
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	_, err = conn.SimpleBind(&SimpleBindRequest{
		Username: input.BindDN,
		Password: input.Password,
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// just rename to uid=new,ou=people,dc=example,dc=org:
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=new", true, "")
	if err = conn.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}

// This example shows how to rename an entry and moving it to a new base
func ExampleConn_ModifyDN_renameAndMove() {
	input := exampleReadCredentials()
	conn, err := exampleDialTLS()
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	_, err = conn.SimpleBind(&SimpleBindRequest{
		Username: input.BindDN,
		Password: input.Password,
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// rename to uid=new,ou=people,dc=example,dc=org and move to ou=users,dc=example,dc=org ->
	// uid=new,ou=users,dc=example,dc=org
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=new", true, "ou=users,dc=example,dc=org")

	if err = conn.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}

// This example shows how to move an entry to a new base without renaming the RDN
func ExampleConn_ModifyDN_moveOnly() {
	input := exampleReadCredentials()
	conn, err := exampleDialTLS()
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	_, err = conn.SimpleBind(&SimpleBindRequest{
		Username: input.BindDN,
		Password: input.Password,
	})
	if err != nil {
		log.Fatalf("Failed to bind: %s\n", err)
	}
	// move to ou=users,dc=example,dc=org -> uid=user,ou=users,dc=example,dc=org
	req := NewModifyDNRequest("uid=user,ou=people,dc=example,dc=org", "uid=user", true, "ou=users,dc=example,dc=org")
	if err = conn.ModifyDN(req); err != nil {
		log.Fatalf("Failed to call ModifyDN(): %s\n", err)
	}
}
