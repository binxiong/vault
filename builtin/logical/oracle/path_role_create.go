package oracle

import (
	"fmt"
    "strings"
    "log"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	_ "github.com/mattn/go-oci8"
)

func formatOraIdentifier(id string) (string, error) {
    r := strings.NewReplacer("-", "_")
    return r.Replace(id), nil
}

func pathRoleCreate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathRoleCreateRead,
		},

		HelpSynopsis:    pathRoleCreateReadHelpSyn,
		HelpDescription: pathRoleCreateReadHelpDesc,
	}
}

func (b *backend) pathRoleCreateRead(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	// Get the role
	role, err := b.Role(req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", name)), nil
	}

    log.Println(fmt.Sprintf("name: %s", name))

	// Determine if we have a lease
	lease, err := b.Lease(req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	// Generate our username and password. Oracle limits user to 16 characters
	displayName := req.DisplayName
	if len(displayName) > 10 {
		displayName = displayName[:10]
	}

	userUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

    userUUID, err = formatOraIdentifier(userUUID)
	if err != nil {
		return nil, err
	}

	username := fmt.Sprintf("%s_%s", displayName, userUUID)
	if len(username) > 30 {
		username = username[:30]
	}
	pwdUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

    pwdUUID, err = formatOraIdentifier(pwdUUID)
	if err != nil {
		return nil, err
	}

    password := fmt.Sprintf("%s%s", "p", pwdUUID)
    if len(password) > 24 {
        password = password[:24]
    }

    log.Println(fmt.Sprintf("username: %s", username))
    log.Println(fmt.Sprintf("password: %s", password))

	// Get our connection
	db, err := b.DB(req.Storage)
	if err != nil {
		return nil, err
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Execute each query
	for _, query := range SplitSQL(role.SQL) {
		stmt, err := db.Prepare(Query(query, map[string]string{
			"name":     username,
			"password": password,
		}))
		if err != nil {
			return nil, err
		}

        log.Println(fmt.Sprintf("sql: %s", stmt))
            
		if _, err := stmt.Exec(); err != nil {
			return nil, err
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Return the secret
	resp := b.Secret(SecretCredsType).Response(map[string]interface{}{
		"username": username,
		"password": password,
	}, map[string]interface{}{
		"username": username,
	})
	resp.Secret.TTL = lease.Lease
	return resp, nil
}

const pathRoleCreateReadHelpSyn = `
Request database credentials for a certain role.
`

const pathRoleCreateReadHelpDesc = `
This path reads database credentials for a certain role. The
database credentials will be generated on demand and will be automatically
revoked when the lease is up.
`
