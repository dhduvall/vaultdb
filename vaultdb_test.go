package vaultdb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	// "bg/common/briefpg"

	vaultapi "github.com/hashicorp/vault/api"
	logicalDb "github.com/hashicorp/vault/builtin/logical/database"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// testVaultServer is based largely on testVaultServerCoreConfig from
// command/command_test.go in the vault repo.
func testVaultServer(t *testing.T) (*vaultapi.Client, func()) {
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		LogicalBackends: map[string]logical.Factory{
			"database": logicalDb.Factory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    1,
	})
	cluster.Start()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)

	client := cluster.Cores[0].Client
	client.SetToken(cluster.RootToken)

	return client, func() { defer cluster.Cleanup() }
}

type vaultConfig struct {
	dbURI string
	path  string
	vcl   *vaultapi.Logical
}

func (vconf vaultConfig) createRole(t *testing.T, role string, ttl, maxTTL int) {
	_, err := vconf.vcl.Write(vconf.path+"/config/db", map[string]interface{}{
		"allowed_roles": role,
	})
	if err != nil {
		t.Fatalf("Failed to configure DB engine in Vault: %v", err)
	}

	// Create a role in Vault that is configured to create a Postgres role
	// with all privileges.
	createSQL := `
		CREATE ROLE "{{name}}" WITH
			LOGIN
			PASSWORD '{{password}}'
			VALID UNTIL '{{expiration}}';
		GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "{{name}}";
	`
	revokeSQL := `
		SELECT pg_terminate_backend(pid)
			FROM pg_stat_activity
			WHERE usename = '{{name}}';
		DROP ROLE IF EXISTS "{{name}}";
	`
	// XXX Should the force-terminate version be optional?
	_, err = vconf.vcl.Write(vconf.path+"/roles/"+role, map[string]interface{}{
		"db_name":               "db",
		"default_ttl":           ttl,
		"max_ttl":               maxTTL,
		"creation_statements":   createSQL,
		"revocation_statements": revokeSQL,
	})
	if err != nil {
		t.Fatalf("Failed to create DB role '%s' in Vault: %v", role, err)
	}

}

// setupVault creates a database and a secrets engine in Vault for it.
func setupVault(t *testing.T, vc *vaultapi.Client, bpg *briefpg.BriefPG) vaultConfig {
	ctx := context.Background()

	dbName := fmt.Sprintf("%s_%d", t.Name(), time.Now().Unix())
	dbURI, err := bpg.CreateDB(ctx, dbName, "")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// The URI Vault uses to access the database needs to be templated for
	// credential information, but the Connector prefers not to have the
	// creds, so we put the former into the Vault database plugin config and
	// hand the latter back to pass to the tests.  Note that we put the
	// creds in as parameters, rather than in the normal position for a URL
	// because various parts of the machinery either can't handle
	// credentials without a host or blow up when path escaping the socket
	// path and putting that in host position.
	cleanDBURI := strings.TrimSuffix(dbURI, "&user=postgres&password=postgres")
	dbURI = cleanDBURI + "&user={{username}}&password={{password}}"
	t.Logf("Database URI: %s", dbURI)

	mi := &vaultapi.MountInput{
		Type: "database",
	}
	path := "database/" + dbName
	if err := vc.Sys().Mount(path, mi); err != nil {
		t.Fatalf("Failed to mount database secrets: %v", err)
	}

	// Configure the database plugin.  The username and password are the
	// "root" credentials.
	vcl := vc.Logical()
	_, err = vcl.Write(path+"/config/db", map[string]interface{}{
		"plugin_name":    "postgresql-database-plugin",
		"connection_url": dbURI,
		"username":       "postgres",
		"password":       "postgres",
	})
	if err != nil {
		t.Fatalf("Failed to configure DB engine in Vault: %v", err)
	}

	return vaultConfig{
		dbURI: cleanDBURI,
		path:  path,
		vcl:   vcl,
	}
}

// fakeVaultAuth mimics vaultgcpauth, except that we log in with the root token,
// and rotate the passed-in client's token with a time-limited sub-token.
func fakeVaultAuth(t *testing.T, vc *vaultapi.Client) (*fanout, chan struct{}) {
	assert := require.New(t)
	notifier := newfanout(make(chan struct{}))
	stopChan := make(chan struct{})

	// We have to get the TokenAuth from a clone of passed-in client, or
	// we'll end up trying to get new tokens using a token that's about to
	// expire.  Note that a Clone() doesn't clone the token, so we set that
	// explicitly.
	rootVC, err := vc.Clone()
	assert.NoError(err)
	rootVC.SetToken(vc.Token())

	tokenAuth := rootVC.Auth().Token()
	tcr := &vaultapi.TokenCreateRequest{TTL: "2s"}
	secret, err := tokenAuth.Create(tcr)
	assert.NoError(err)
	token, err := secret.TokenID()
	assert.NoError(err)
	vc.SetToken(token)

	go func() {
		for {
			renewAt, err := secret.TokenTTL()
			assert.NoError(err)
			renewAt = renewAt * 3 / 4

			select {
			case <-time.After(renewAt):
				secret, err := tokenAuth.Create(tcr)
				assert.NoError(err)
				token, err := secret.TokenID()
				assert.NoError(err)
				vc.SetToken(token)

				notifier.notify()

			case <-stopChan:
				return
			}
		}
	}()

	return notifier, stopChan
}

// testDBSecrets tests the basic functionality of vaultdb: that we can establish
// a connection to the database using credentials from Vault that rotate
// periodically.
func testDBSecrets(t *testing.T, vc *vaultapi.Client, vconf vaultConfig) {
	assert := require.New(t)
	role := "myrole"

	// Use the database via Vault
	vdbc := NewConnector(vconf.dbURI, vc, nil, vconf.path, role,
		zaptest.NewLogger(t).Sugar())
	db := sql.OpenDB(vdbc)
	// This combination is intended to indicate that each statement uses a
	// brand new connection, and that connections won't be reused.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	// This requires the role to be configured, so will return an error.
	err := vdbc.SetConnMaxLifetime(db)
	assert.Error(err)

	// This will attempt to open a connection, thus read creds from vault,
	// thus fail because the role isn't configured.
	err = db.Ping()
	assert.Error(err)

	vconf.createRole(t, role, 2, 5)

	// These should succeed now.
	err = vdbc.SetConnMaxLifetime(db)
	assert.NoError(err)
	err = db.Ping()
	assert.NoError(err)

	watcher, err := vdbc.getWatcher()
	assert.NoError(err)
	go watcher.Start()

	// Make sure we got credentials.
	ephemeralRoleName := vdbc.username()
	assert.NotEmpty(vdbc.username())
	assert.NotEmpty(vdbc.password())

	// We can create an object with the credentials
	_, err = db.Exec("CREATE TABLE test();")
	assert.NoError(err)

	// Verify that the user postgres thinks we are is the same as what Vault
	// told us.
	row := db.QueryRow(`SELECT session_user`)
	assert.NoError(err)
	var sessionUser string
	err = row.Scan(&sessionUser)
	assert.NoError(err)
	assert.Equal(ephemeralRoleName, sessionUser)

	// Wait for a renewal, and drop the table (showing the dropping user is
	// the same as the creating one).
	renewEvent := <-watcher.RenewCh()
	assert.IsType(&vaultapi.RenewOutput{}, renewEvent)
	_, err = db.Exec("DROP TABLE test;")
	assert.NoError(err)

	// Re-create the table; then, wait for the old credentials to expire.
	_, err = db.Exec("CREATE TABLE test();")
	assert.NoError(err)
	doneErr := <-watcher.DoneCh()
	assert.NoError(doneErr)

	// Demonstrate that the new credentials are in use by looking at the
	// session user.  Because the credential rotation isn't happening in a
	// separate goroutine, it will happen in one of the queries in the loop,
	// but we don't know which, in advance.  This is because the "done"
	// notification we got above is not synchronized with the one received
	// in waitWatcher, so we don't have a guarantee that it will have been
	// delivered by the time we next call it.
	for start := time.Now(); err == nil &&
		sessionUser == ephemeralRoleName &&
		time.Now().Before(start.Add(time.Second)); time.Sleep(50 * time.Millisecond) {
		err = db.QueryRow(`SELECT session_user`).Scan(&sessionUser)
	}
	assert.NoError(err)
	assert.NotEqual(ephemeralRoleName, sessionUser)

	// Also, we can create new objects, but are unable to modify objects in
	// use by the old user.
	_, err = db.Exec("CREATE TABLE test2();")
	assert.NoError(err)
	_, err = db.Exec("DROP TABLE test;")
	assert.Error(err)

	// Run a query that creates objects at the beginning and the end, and is
	// long enough that it would have to straddle credential rotation.
	ephemeralRoleName = vdbc.username()
	_, err = db.Exec("CREATE TABLE test3(); SELECT pg_sleep(5); CREATE TABLE test4();")
	assert.NoError(err)
	_, err = db.Exec("SELECT 1")
	assert.NoError(err)
	assert.NotEmpty(vdbc.username())
	assert.NotEmpty(vdbc.password())
	assert.NotEqual(ephemeralRoleName, vdbc.username())

	// Make sure that table ownership is as expected; both tables created in
	// the previous statement, despite crossing a credential rotation, are
	// owned by the same user, but they're different from the owner of the
	// previous one.
	rows, err := db.Query(`
		SELECT tablename, tableowner
		FROM pg_tables
		WHERE tablename IN ('test', 'test3', 'test4')`)
	assert.NoError(err)
	owners := make(map[string]string)
	for rows.Next() {
		var owner, table string
		err = rows.Scan(&table, &owner)
		assert.NoError(err)
		owners[table] = owner
	}
	assert.NotEqual(owners["test2"], owners["test3"])
	assert.Equal(owners["test3"], owners["test4"])
}

// testMultiVDBC tests two things.  One is when authentication to Vault is done
// with a time-limited token, that sub-leases (such as database credentials) are
// appropriately expired and new credentials can be retrieved under the new auth
// token.  The second is that we can have more than one Connector based on a
// single vault client and that the authentication notification doesn't fall
// into any deadlocks when we get a new auth token.
func testMultiVDBC(t *testing.T, vc *vaultapi.Client, vconf vaultConfig) {
	assert := require.New(t)

	role := "myrole"
	vconf.createRole(t, role, 2, 5)

	notifier, stopChan := fakeVaultAuth(t, vc)
	defer func() { stopChan <- struct{}{} }()

	vdbc1 := NewConnector(vconf.dbURI, vc, notifier, vconf.path, role,
		zaptest.NewLogger(t).Named("vdbc1").Sugar())

	vdbc2 := NewConnector(vconf.dbURI, vc, notifier, vconf.path, role,
		zaptest.NewLogger(t).Named("vdbc2").Sugar())

	db1 := sql.OpenDB(vdbc1)
	db1.SetMaxOpenConns(1)
	db1.SetMaxIdleConns(0)

	db2 := sql.OpenDB(vdbc2)
	db2.SetMaxOpenConns(1)
	db2.SetMaxIdleConns(0)

	start := time.Now()
	end := start.Add(5 * time.Second)
	for time.Now().Before(end) {
		err := db1.Ping()
		assert.NoError(err)
		time.Sleep(time.Second / 4)
		err = db2.Ping()
		assert.NoError(err)
		time.Sleep(time.Second / 4)
	}
}

func testCredentialRevocation(t *testing.T, vc *vaultapi.Client, vconf vaultConfig) {
	// assert := require.New(t)

	role := "something"
	vconf.createRole(t, role, 1, 1)

	vdbc := NewConnector(vconf.dbURI, vc, nil, vconf.path, role,
		zaptest.NewLogger(t).Named("something").Sugar())

	db := sql.OpenDB(vdbc)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	// This sleep should be interrupted by the revocation statements
	// terminating the session, but they never seem to get executed.
	start := time.Now()
	ch := make(chan error)
	go func() {
		_, err := db.Exec("SELECT pg_sleep(3)")
		ch <- err
	}()
	time.Sleep(500 * time.Millisecond)
	// We see a stack with the watcher in it here
	pprof.Lookup("goroutine").WriteTo(os.Stdout, 2)
	time.Sleep(1000 * time.Millisecond)
	fmt.Println("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	// But not here, since the watcher has completed, and we haven't been
	// asked for a new secret, with a new watcher.
	pprof.Lookup("goroutine").WriteTo(os.Stdout, 2)
	err := <-ch
	t.Log(time.Now().Sub(start))
	t.Log(err)
}

func TestEmAll(t *testing.T) {
	var ctx = context.Background()

	// Set up the database
	bpg := briefpg.New(nil)
	if err := bpg.Start(ctx); err != nil {
		t.Fatalf("Failed to start Postgres: %v", err)
	}
	defer bpg.Fini(ctx)

	testCases := []struct {
		name  string
		tFunc func(*testing.T, *vaultapi.Client, vaultConfig)
	}{
		{"testDBSecrets", testDBSecrets},
		{"testMultiVDBC", testMultiVDBC},
		{"testCredentialRevocation", testCredentialRevocation},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vc, vStop := testVaultServer(t)
			defer vStop()

			vconf := setupVault(t, vc, bpg)
			tc.tFunc(t, vc, vconf)
		})
	}

}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
