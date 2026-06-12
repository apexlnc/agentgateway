package oidc

import (
	"fmt"

	"istio.io/istio/pkg/kube/krt"
)

type Lookup interface {
	ResolveForOwner(krtctx krt.HandlerContext, owner RemoteOidcOwner) (*DiscoveredProvider, error)
}

type lookupImpl struct {
	resolver  Resolver
	persisted *PersistedEntries
}

// NewLookup resolves providers from the persisted collection so translation
// recomputes when discovery persistence changes. Uses the same Resolver as
// the fetch store, so direct-issuer and BackendRef paths derive identical
// request keys.
func NewLookup(persisted *PersistedEntries, resolver Resolver) Lookup {
	return &lookupImpl{
		resolver:  resolver,
		persisted: persisted,
	}
}

func (l *lookupImpl) ResolveForOwner(krtctx krt.HandlerContext, owner RemoteOidcOwner) (*DiscoveredProvider, error) {
	if l.persisted == nil {
		return nil, fmt.Errorf("oidc provider lookup is not configured")
	}
	if l.resolver == nil {
		return nil, fmt.Errorf("oidc resolver is not configured")
	}

	resolved, err := l.resolver.ResolveOwner(krtctx, owner)
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return nil, fmt.Errorf("oidc resolver returned nil request")
	}

	requestKey := oidcRequestKey(resolved.Target.Target, resolved.ExpectedIssuer, resolved.ProviderBackendTarget)
	provider, ok := l.persisted.CanonicalGet(krtctx, requestKey)
	if !ok {
		return nil, fmt.Errorf("oidc provider for %q isn't available (not yet fetched or fetch failed)", resolved.Target.Target.URL)
	}
	return &provider, nil
}
