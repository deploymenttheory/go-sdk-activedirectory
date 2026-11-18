package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

// This example demonstrates how to bind a connection to an ldap user
// allowing access to restricted attributes that user has access to
func ExampleConn_Bind() {
	input := exampleReadCredentials()
	l, err := exampleDialTLS()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	err = l.Bind(input.BindDN, input.Password)
	if err != nil {
		log.Fatal(err)
	}
}

// This example demonstrates how to use the search interface
func ExampleConn_Search() {
	l, err := exampleDialAndBind()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	searchRequest := NewSearchRequest(
		"dc=example,dc=com", // The base dn to search
		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		"(&(objectClass=organizationalPerson))", // The filter to apply
		[]string{"dn", "cn"},                    // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range sr.Entries {
		fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
	}
}

// This example demonstrates how to search asynchronously
func ExampleConn_SearchAsync() {
	l, err := exampleDialAndBind()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	searchRequest := NewSearchRequest(
		"dc=example,dc=com", // The base dn to search
		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		"(&(objectClass=organizationalPerson))", // The filter to apply
		[]string{"dn", "cn"},                    // A list attributes to retrieve
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := l.SearchAsync(ctx, searchRequest, 64)
	for r.Next() {
		entry := r.Entry()
		fmt.Printf("%s has DN %s\n", entry.GetAttributeValue("cn"), entry.DN)
	}
	if err := r.Err(); err != nil {
		log.Fatal(err)
	}
}

// This example demonstrates how to do syncrepl (persistent search)
func ExampleConn_Syncrepl() {
	l, err := exampleDialAndBind()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	searchRequest := NewSearchRequest(
		"dc=example,dc=com", // The base dn to search
		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		"(&(objectClass=organizationalPerson))", // The filter to apply
		[]string{"dn", "cn"},                    // A list attributes to retrieve
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mode := SyncRequestModeRefreshAndPersist
	var cookie []byte = nil
	r := l.Syncrepl(ctx, searchRequest, 64, mode, cookie, false)
	for r.Next() {
		entry := r.Entry()
		if entry != nil {
			fmt.Printf("%s has DN %s\n", entry.GetAttributeValue("cn"), entry.DN)
		}
		controls := r.Controls()
		if len(controls) != 0 {
			fmt.Printf("%s", controls)
		}
	}
	if err := r.Err(); err != nil {
		log.Fatal(err)
	}
}

// This example demonstrates how to start a TLS connection
func ExampleConn_StartTLS() {
	input := exampleReadCredentials()
	l, err := DialURL("ldap://ldap.example.com:389", DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// Reconnect with TLS
	err = l.StartTLS(exampleTLSConfig())
	if err != nil {
		log.Fatal(err)
	}

	if err := l.Bind(input.BindDN, input.Password); err != nil {
		log.Fatal("verified TLS bind failed")
	}
	// Operations via l are now authenticated over verified TLS.
}

// This example demonstrates how to compare an attribute with a value
func ExampleConn_Compare() {
	l, err := exampleDialAndBind()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	matched, err := l.Compare("cn=user,dc=example,dc=com", "uid", "someuserid")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(matched)
}

func ExampleConn_PasswordModify_admin() {
	input := exampleReadCredentials()
	if input.NewPassword == "" {
		log.Fatal("new_password is required")
	}
	l, err := exampleDialTLS()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	err = l.Bind(input.BindDN, input.Password)
	if err != nil {
		log.Fatal(err)
	}

	passwordModifyRequest := NewPasswordModifyRequest("cn=user,dc=example,dc=com", "", input.NewPassword)
	_, err = l.PasswordModify(passwordModifyRequest)
	if err != nil {
		log.Fatalf("Password could not be changed: %s", err.Error())
	}
}

func ExampleConn_PasswordModify_generatedPassword() {
	input := exampleReadCredentials()
	if input.OldPassword == "" {
		log.Fatal("old_password is required")
	}
	l, err := exampleDialTLS()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	err = l.Bind(input.BindDN, input.Password)
	if err != nil {
		log.Fatal(err)
	}

	passwordModifyRequest := NewPasswordModifyRequest("", input.OldPassword, "")
	passwordModifyResponse, err := l.PasswordModify(passwordModifyRequest)
	if err != nil {
		log.Fatalf("Password could not be changed: %s", err.Error())
	}

	// Deliver GeneratedPassword directly to your secret manager; never print it.
	_ = passwordModifyResponse.GeneratedPassword
}

func ExampleConn_PasswordModify_setNewPassword() {
	input := exampleReadCredentials()
	if input.OldPassword == "" || input.NewPassword == "" {
		log.Fatal("old_password and new_password are required")
	}
	l, err := exampleDialTLS()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	err = l.Bind(input.BindDN, input.Password)
	if err != nil {
		log.Fatal(err)
	}

	passwordModifyRequest := NewPasswordModifyRequest("", input.OldPassword, input.NewPassword)
	_, err = l.PasswordModify(passwordModifyRequest)
	if err != nil {
		log.Fatalf("Password could not be changed: %s", err.Error())
	}
}

func ExampleConn_Modify() {
	l, err := exampleDialAndBind()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// Add a description, and replace the mail attributes
	modify := NewModifyRequest("cn=user,dc=example,dc=com", nil)
	modify.Add("description", []string{"An example user"})
	modify.Replace("mail", []string{"user@example.org"})

	err = l.Modify(modify)
	if err != nil {
		log.Fatal(err)
	}
}

// Example_userAuthentication shows how a typical application can verify a login attempt
// Refer to https://github.com/go-ldap/ldap/issues/93 for issues revolving around unauthenticated binds, with zero length passwords
func Example_userAuthentication() {
	input := exampleReadCredentials()
	if input.UserName == "" || input.UserPassword == "" {
		log.Fatal("user_name and user_password are required")
	}
	// The username and password we want to check
	username := input.UserName
	password := input.UserPassword

	bindusername := input.BindDN
	bindpassword := input.Password

	l, err := exampleDialTLS()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// First bind with a read only user
	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		log.Fatal(err)
	}

	// Search for the given username
	searchRequest := NewSearchRequest(
		"dc=example,dc=com",
		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) != 1 {
		log.Fatal("User does not exist or too many entries returned")
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, password)
	if err != nil {
		log.Fatal(err)
	}

	// Rebind as the read only user for any further queries
	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		log.Fatal(err)
	}
}

func Example_beherappolicy() {
	input := exampleReadCredentials()
	l, err := exampleDialTLS()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	controls := []Control{}
	controls = append(controls, NewControlBeheraPasswordPolicy())
	bindRequest := NewSimpleBindRequest(input.BindDN, input.Password, controls)

	r, err := l.SimpleBind(bindRequest)
	if r == nil {
		log.Fatal("bind returned no LDAP result")
	}
	ppolicyControl := FindControl(r.Controls, ControlTypeBeheraPasswordPolicy)

	var ppolicy *ControlBeheraPasswordPolicy
	if ppolicyControl != nil {
		ppolicy = ppolicyControl.(*ControlBeheraPasswordPolicy)
	} else {
		log.Printf("ppolicyControl response not available.\n")
	}
	if err != nil {
		errStr := "ERROR: Cannot bind: " + err.Error()
		if ppolicy != nil && ppolicy.Error >= 0 {
			errStr += ":" + ppolicy.ErrorString
		}
		log.Print(errStr)
	} else {
		logStr := "Login Ok"
		if ppolicy != nil {
			if ppolicy.Expire >= 0 {
				logStr += fmt.Sprintf(". Password expires in %d seconds\n", ppolicy.Expire)
			} else if ppolicy.Grace >= 0 {
				logStr += fmt.Sprintf(". Password expired, %d grace logins remain\n", ppolicy.Grace)
			}
		}
		log.Print(logStr)
	}
}

func Example_vchuppolicy() {
	input := exampleReadCredentials()
	l, err := exampleDialTLS()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	bindRequest := NewSimpleBindRequest(input.BindDN, input.Password, nil)

	r, err := l.SimpleBind(bindRequest)
	if r == nil {
		log.Fatal("bind returned no LDAP result")
	}

	passwordMustChangeControl := FindControl(r.Controls, ControlTypeVChuPasswordMustChange)
	var passwordMustChange *ControlVChuPasswordMustChange
	if passwordMustChangeControl != nil {
		passwordMustChange = passwordMustChangeControl.(*ControlVChuPasswordMustChange)
	}

	if passwordMustChange != nil && passwordMustChange.MustChange {
		log.Printf("Password Must be changed.\n")
	}

	passwordWarningControl := FindControl(r.Controls, ControlTypeVChuPasswordWarning)

	var passwordWarning *ControlVChuPasswordWarning
	if passwordWarningControl != nil {
		passwordWarning = passwordWarningControl.(*ControlVChuPasswordWarning)
	} else {
		log.Printf("ppolicyControl response not available.\n")
	}
	if err != nil {
		log.Print("ERROR: Cannot bind: " + err.Error())
	} else {
		logStr := "Login Ok"
		if passwordWarning != nil {
			if passwordWarning.Expire >= 0 {
				logStr += fmt.Sprintf(". Password expires in %d seconds\n", passwordWarning.Expire)
			}
		}
		log.Print(logStr)
	}
}

// This example demonstrates how to use ControlPaging to manually execute a
// paginated search request instead of using SearchWithPaging.
func ExampleControlPaging_manualPaging() {
	conn, err := exampleDialAndBind()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	var pageSize uint32 = 32
	searchBase := "dc=example,dc=com"
	filter := "(objectClass=group)"
	pagingControl := NewControlPaging(pageSize)
	attributes := []string{}
	controls := []Control{pagingControl}

	for {
		request := NewSearchRequest(searchBase, ScopeWholeSubtree, DerefAlways, 0, 0, false, filter, attributes, controls)
		response, err := conn.Search(request)
		if err != nil {
			log.Fatalf("Failed to execute search request: %s", err.Error())
		}

		// [do something with the response entries]

		// In order to prepare the next request, we check if the response
		// contains another ControlPaging object and a not-empty cookie and
		// copy that cookie into our pagingControl object:
		updatedControl := FindControl(response.Controls, ControlTypePaging)
		if ctrl, ok := updatedControl.(*ControlPaging); ctrl != nil && ok && len(ctrl.Cookie) != 0 {
			pagingControl.SetCookie(ctrl.Cookie)
			continue
		}
		// If no new paging information is available or the cookie is empty, we
		// are done with the pagination.
		break
	}
}

// This example demonstrates how to use DirSync to manually execute a
// DirSync search request
func ExampleConn_DirSync() {
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
		log.Fatalf("failed to bind: %s", err)
	}

	req := &SearchRequest{
		BaseDN:     `DC=example,DC=org`,
		Filter:     `(&(objectClass=person)(!(objectClass=computer)))`,
		Attributes: []string{"*"},
		Scope:      ScopeWholeSubtree,
	}
	// This is the initial sync with all entries matching the filter
	doMore := true
	var cookie []byte
	for doMore {
		res, err := conn.DirSync(req, DirSyncObjectSecurity, 1000, cookie)
		if err != nil {
			log.Fatalf("failed to search: %s", err)
		}
		for _, entry := range res.Entries {
			entry.Print()
		}
		ctrl := FindControl(res.Controls, ControlTypeDirSync)
		if ctrl == nil || ctrl.(*ControlDirSync).Flags == 0 {
			doMore = false
		}
		cookie = ctrl.(*ControlDirSync).Cookie
	}
	// We're done with the initial sync. Now pull every 15 seconds for the
	// updated entries - note that you get just the changes, not a full entry.
	for {
		res, err := conn.DirSync(req, DirSyncObjectSecurity, 1000, cookie)
		if err != nil {
			log.Fatalf("failed to search: %s", err)
		}
		for _, entry := range res.Entries {
			entry.Print()
		}
		time.Sleep(15 * time.Second)
	}
}

// This example demonstrates how to use DirSync search asynchronously
func ExampleConn_DirSyncAsync() {
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
		log.Fatalf("failed to bind: %s", err)
	}

	req := &SearchRequest{
		BaseDN:     `DC=example,DC=org`,
		Filter:     `(&(objectClass=person)(!(objectClass=computer)))`,
		Attributes: []string{"*"},
		Scope:      ScopeWholeSubtree,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cookie []byte = nil
	r := conn.DirSyncAsync(ctx, req, 64, DirSyncObjectSecurity, 1000, cookie)
	for r.Next() {
		entry := r.Entry()
		if entry != nil {
			entry.Print()
		}
		controls := r.Controls()
		if len(controls) != 0 {
			fmt.Printf("%s", controls)
		}
	}
	if err := r.Err(); err != nil {
		log.Fatal(err)
	}
}

// This example demonstrates how to use EXTERNAL SASL with TLS client certificates.
func ExampleConn_ExternalBind() {
	ldapCert := "/path/to/cert.pem"
	ldapKey := "/path/to/key.pem"
	ldapCAchain := "/path/to/ca_chain.pem"

	// Load client cert and key
	cert, err := tls.LoadX509KeyPair(ldapCert, ldapKey)
	if err != nil {
		log.Fatal(err)
	}

	// Load CA chain
	caCert, err := os.ReadFile(ldapCAchain)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("invalid CA bundle")
	}

	// Setup TLS with ldap client cert
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   "ldap.example.com",
	}

	// connect to ldap server
	l, err := DialURL("ldap://ldap.example.com:389", DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// reconnect using tls
	err = l.StartTLS(tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	// sasl external bind
	err = l.ExternalBind()
	if err != nil {
		log.Fatal(err)
	}

	// Conduct ldap queries
}

// ExampleConn_WhoAmI demonstrates how to run a whoami request according to https://tools.ietf.org/html/rfc4532
func ExampleConn_WhoAmI() {
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

	res, err := conn.WhoAmI(nil)
	if err != nil {
		log.Fatalf("Failed to call WhoAmI(): %s\n", err)
	}
	fmt.Printf("I am: %s\n", res.AuthzID)
}

// exampleSecretInput is supplied through protected redirected stdin, never argv.
// Add operation-specific fields only when running the corresponding example.
type exampleSecretInput struct {
	BindDN       string `json:"bind_dn"`
	Password     string `json:"password"`
	UserName     string `json:"user_name"`
	UserPassword string `json:"user_password"`
	OldPassword  string `json:"old_password"`
	NewPassword  string `json:"new_password"`
}

func exampleReadCredentials() exampleSecretInput {
	const limit = 64 << 10
	data, err := io.ReadAll(io.LimitReader(os.Stdin, limit+1))
	if err != nil || len(data) > limit {
		log.Fatal("bounded credential JSON is required on stdin")
	}
	defer clear(data)
	var input exampleSecretInput
	if err := json.Unmarshal(data, &input); err != nil || input.BindDN == "" || input.Password == "" {
		log.Fatal("nonempty bind_dn and password are required in stdin JSON")
	}
	return input
}

func exampleTLSConfig() *tls.Config {
	// Replace the example FQDN consistently in the URL, ServerName and SPN.
	// RootCAs=nil uses system trust; install your private root before running.
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "ldap.example.com"}
}

func exampleDialTLS() (*Conn, error) {
	conn, err := DialURL("ldaps://ldap.example.com:636",
		DialWithTLSConfig(exampleTLSConfig()),
		DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	if err == nil {
		conn.SetTimeout(10 * time.Second)
	}
	return conn, err
}

func exampleDialAndBind() (*Conn, error) {
	input := exampleReadCredentials()
	conn, err := exampleDialTLS()
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(input.BindDN, input.Password); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
