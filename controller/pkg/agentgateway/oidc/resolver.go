package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

const discoveryPath = "/.well-known/openid-configuration"

var errResolverNotInitialized = errors.New("remote http resolver hasn't been initialized")

// ResolvedOidcRequest packages the resolved fetch target and trust identity
// for one OIDC owner. It is the input to the shared-request collapse step.
type ResolvedOidcRequest struct {
	OwnerID        remotecache.OwnerID
	Target         remotehttp.ResolvedTarget
	ExpectedIssuer string
	TTL            time.Duration
}

// Resolver translates a per-owner RemoteOidcOwner into a fully resolved
// fetch target — including the discovery URL and any per-backend TLS
// material derived from an attached AgentgatewayPolicy.
type Resolver interface {
	ResolveOwner(krtctx krt.HandlerContext, owner RemoteOidcOwner) (*ResolvedOidcRequest, error)
}

type defaultResolver struct {
	endpointResolver remotehttp.Resolver
}

// NewResolver wires the OIDC resolver to the shared remotehttp.Resolver so
// BackendRef-based OIDC fetches reuse the same backend → TLS plumbing as
// JWKS, attached MCP authentication, and other backend-driven fetchers.
func NewResolver(endpointResolver remotehttp.Resolver) Resolver {
	return &defaultResolver{endpointResolver: endpointResolver}
}

func (r *defaultResolver) ResolveOwner(krtctx krt.HandlerContext, owner RemoteOidcOwner) (*ResolvedOidcRequest, error) {
	discURL, err := discoveryURL(owner.Config.IssuerURL)
	if err != nil {
		return nil, err
	}

	endpoint, err := resolveEndpoint(krtctx, r.endpointResolver, owner.ID.Name, owner.DefaultNamespace, owner.Config, discURL)
	if err != nil {
		return nil, err
	}

	return &ResolvedOidcRequest{
		OwnerID:        owner.ID,
		Target:         *endpoint,
		ExpectedIssuer: owner.Config.IssuerURL,
		TTL:            owner.TTL,
	}, nil
}

// discoveryURL constructs the OIDC well-known configuration endpoint URL from the given issuer URL.
// It verifies that the issuer URL is a valid, absolute HTTPS URL with no query or fragment.
func discoveryURL(issuerURL string) (string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", fmt.Errorf("invalid issuer URL %q: %w", issuerURL, err)
	}
	if !u.IsAbs() || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("issuer URL must be absolute HTTPS with a host and no query or fragment")
	}
	return u.JoinPath(".well-known", "openid-configuration").String(), nil
}

// resolveEndpoint produces the transport target for an OIDC discovery fetch.
// Without BackendRef: hit discoveryURL with the system trust store.
// With BackendRef: resolver derives URL + TLS from the referenced Service or
// Backend, applying attached AgentgatewayPolicy backend TLS settings.
func resolveEndpoint(
	krtctx krt.HandlerContext,
	resolver remotehttp.Resolver,
	policyName, defaultNS string,
	cfg agentgateway.OIDC,
	discURL string,
) (*remotehttp.ResolvedTarget, error) {
	if cfg.BackendRef == nil {
		target := remotehttp.FetchTarget{URL: discURL}
		return &remotehttp.ResolvedTarget{
			Key:    target.Key(),
			Target: target,
		}, nil
	}

	if resolver == nil {
		return nil, errResolverNotInitialized
	}

	return resolver.Resolve(krtctx, remotehttp.ResolveInput{
		ParentName:       policyName,
		DefaultNamespace: defaultNS,
		BackendRef:       *cfg.BackendRef,
		Path:             discoveryPath,
	})
}
