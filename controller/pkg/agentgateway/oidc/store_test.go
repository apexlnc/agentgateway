package oidc

import (
	"testing"
	"time"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

func newTestOIDCStore() *OIDCStore {
	cache := NewProviderCache()
	return &OIDCStore{
		providerCache:   cache,
		providerFetcher: NewProviderFetcher(cache),
		ownerToSource:   make(map[OwnerKey]ProviderSource),
		requestToOwner:  make(map[remotehttp.FetchKey]map[OwnerKey]struct{}),
	}
}

func testProviderSource(owner OwnerKey, ttl time.Duration) ProviderSource {
	return ProviderSource{
		OwnerKey:   owner,
		Issuer:     testOIDCIssuer,
		RequestKey: remotehttp.FetchKey("shared-provider"),
		Target: remotehttp.FetchTarget{
			URL: "https://issuer.example.com/.well-known/openid-configuration",
		},
		TTL: ttl,
	}
}

func TestOIDCStoreUsesMinimumTTLForSharedProviderSources(t *testing.T) {
	t.Parallel()

	store := newTestOIDCStore()
	store.handleSourceChange(testProviderSource("policy/default/a", 10*time.Minute))
	store.handleSourceChange(testProviderSource("policy/default/b", time.Minute))

	source, ok := store.providerFetcher.sources[remotehttp.FetchKey("shared-provider")]
	if !ok {
		t.Fatal("expected shared provider source to be registered")
	}
	if source.TTL != time.Minute {
		t.Fatalf("expected minimum TTL of 1m, got %s", source.TTL)
	}
}

func TestOIDCStoreRecomputesSharedTTLWhenOwnerIsRemoved(t *testing.T) {
	t.Parallel()

	store := newTestOIDCStore()
	store.handleSourceChange(testProviderSource("policy/default/a", 10*time.Minute))
	store.handleSourceChange(testProviderSource("policy/default/b", time.Minute))
	store.handleSourceChange(ProviderSource{OwnerKey: "policy/default/b", Deleted: true})

	source, ok := store.providerFetcher.sources[remotehttp.FetchKey("shared-provider")]
	if !ok {
		t.Fatal("expected shared provider source to remain registered")
	}
	if source.TTL != 10*time.Minute {
		t.Fatalf("expected TTL to fall back to remaining owner TTL, got %s", source.TTL)
	}

	store.handleSourceChange(ProviderSource{OwnerKey: "policy/default/a", Deleted: true})
	if _, ok := store.providerFetcher.sources[remotehttp.FetchKey("shared-provider")]; ok {
		t.Fatal("expected shared provider source to be removed when last owner is deleted")
	}
}
