package oidc

import (
	"errors"
	"fmt"
	"net/url"

	"istio.io/istio/pkg/kube/krt"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

var (
	errResolverNotInitialized = errors.New("remote http resolver hasn't been initialized")
)

// defaultResolver implements Resolver using the shared remotehttp.Resolver.
type defaultResolver struct {
	endpointResolver remotehttp.Resolver
}

// NewResolver constructs a Resolver backed by the given remotehttp.Resolver.
func NewResolver(endpointResolver remotehttp.Resolver) Resolver {
	return &defaultResolver{endpointResolver: endpointResolver}
}

func (r *defaultResolver) ResolveOwner(krtctx krt.HandlerContext, owner RemoteOidcOwner) (*ResolvedOidcRequest, error) {
	endpoint, err := resolveOidcEndpoint(krtctx, r.endpointResolver, owner)
	if err != nil {
		return nil, err
	}

	return &ResolvedOidcRequest{
		OwnerID: owner.ID,
		Target:  *endpoint,
		TTL:     owner.TTL,
	}, nil
}

// resolveOidcEndpoint resolves the OIDC discovery URL for the given owner.
// If the owner has a Backend reference, use it; otherwise build a direct URL
// from the IssuerURL.
func resolveOidcEndpoint(
	krtctx krt.HandlerContext,
	resolver remotehttp.Resolver,
	owner RemoteOidcOwner,
) (*remotehttp.ResolvedTarget, error) {
	if resolver == nil {
		return nil, errResolverNotInitialized
	}

	issuerURL := owner.Config.IssuerURL
	discoveryPath := ".well-known/openid-configuration"

	if owner.Config.Backend != nil {
		// Route discovery through the specified backend.
		return resolver.Resolve(krtctx, remotehttp.ResolveInput{
			ParentName:       owner.ID.Name,
			DefaultNamespace: owner.DefaultNamespace,
			BackendRef:       backendRef(owner.Config.Backend),
			Path:             discoveryPath,
		})
	}

	// Direct fetch: build the discovery URL from the issuer.
	discoveryURL, err := oidcDiscoveryURL(issuerURL)
	if err != nil {
		return nil, err
	}

	target := remotehttp.FetchTarget{URL: discoveryURL}
	return &remotehttp.ResolvedTarget{
		Key:    target.Key(),
		Target: target,
	}, nil
}

// oidcDiscoveryURL returns <issuerURL>/.well-known/openid-configuration,
// handling the case where issuerURL already has a path component per RFC 8414.
func oidcDiscoveryURL(issuerURL string) (string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", fmt.Errorf("invalid issuer URL %q: %w", issuerURL, err)
	}
	// RFC 8414 §3: append /.well-known/openid-configuration to the issuer URL.
	// If the issuer URL already has a non-root path, the discovery document is
	// at /.well-known/openid-configuration/<path-suffix>.
	base := *u
	if base.Path == "" || base.Path == "/" {
		base.Path = "/.well-known/openid-configuration"
	} else {
		base.Path = "/.well-known/openid-configuration" + base.Path
	}
	return base.String(), nil
}

// backendRef converts a gateway BackendObjectReference to the remotehttp type.
func backendRef(b *gwv1.BackendObjectReference) gwv1.BackendObjectReference {
	if b == nil {
		return gwv1.BackendObjectReference{}
	}
	return *b
}
