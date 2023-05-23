package mock

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"tailscale.com/client/tailscale"
)

// backend wraps the backend framework and adds a map for storing key value pairs.
type backend struct {
	*framework.Backend
	lc *tailscale.LocalClient
}

var _ logical.Factory = Factory

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*backend, error) {
	b := &backend{
		lc: &tailscale.LocalClient{},
	}

	b.Backend = &framework.Backend{
		Help:        "Authenticate using a Tailscale mesh",
		BackendType: logical.TypeCredential,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathLogin(),
			},
		),
	}

	return b, nil
}

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields:  map[string]*framework.FieldSchema{},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Log in using tailscale",
			},
		},
	}
}

func (b *backend) handleLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	hp := net.JoinHostPort(req.Connection.RemoteAddr, strconv.Itoa(req.Connection.RemotePort))

	// lookup the user information based on the host port
	who, err := b.lc.WhoIs(ctx, hp)
	if err != nil {
		return nil, fmt.Errorf("failed tailscale.WhoIs: %w", err)
	}

	policies := []string{}
	var alias *logical.Alias

	if len(who.Node.Tags) > 0 {
		// Node tags are mapped to policies like tag:foo -> tailscale/foo.
		policies = append(policies, buildPolicies(who.Node.Tags)...)
	} else {
		// If there are no tags, we'll use the user profile information
		// as an alias.
		alias = &logical.Alias{
			Name: who.UserProfile.LoginName,
			CustomMetadata: map[string]string{
				"display_name": who.UserProfile.DisplayName,
			},
		}
	}

	// Compose the response
	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{},
			Policies:     policies,
			Metadata: map[string]string{
				"name": who.Node.ComputedName,
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:    2 * time.Minute,
				MaxTTL: 2 * time.Minute,
			},
			Alias: alias,
		},
	}, nil
}

func buildPolicies(tags []string) []string {
	policies := []string{}
	for _, tag := range tags {
		policies = append(policies, fmt.Sprintf("tailscale/%s", strings.TrimPrefix(tag, "tag:")))
	}
	return policies
}
