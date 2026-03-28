package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

func TestStoreAppliesOwnerUpdatesBySharedRequestKey(t *testing.T) {
	store := &Store{
		providerCache:      newCache(),
		sourcesByOwner:     make(map[OwnerKey]ProviderSource),
		ownersByRequestKey: make(map[remotehttp.FetchKey]map[OwnerKey]ProviderSource),
	}

	first := testSource("one", 5*time.Minute)
	second := testSource("two", 2*time.Minute)
	second.RequestKey = first.RequestKey
	second.Target = first.Target

	update := store.applyOwnerUpdate(first)
	if assert.Len(t, update.actions, 1) {
		assert.False(t, update.actions[0].delete)
		assert.NotNil(t, update.actions[0].upsert)
		assert.Equal(t, first.TTL, update.actions[0].upsert.TTL)
	}

	update = store.applyOwnerUpdate(second)
	if assert.Len(t, update.actions, 1) {
		assert.False(t, update.actions[0].delete)
		assert.NotNil(t, update.actions[0].upsert)
		assert.Equal(t, second.TTL, update.actions[0].upsert.TTL)
	}
}

func TestStoreDeletesProviderRequestWhenLastOwnerIsRemoved(t *testing.T) {
	store := &Store{
		providerCache:      newCache(),
		sourcesByOwner:     make(map[OwnerKey]ProviderSource),
		ownersByRequestKey: make(map[remotehttp.FetchKey]map[OwnerKey]ProviderSource),
	}

	source := testSource("one", 5*time.Minute)
	store.applyOwnerUpdate(source)

	remove := store.removeOwner(source.OwnerKey)
	if assert.Len(t, remove.actions, 1) {
		assert.True(t, remove.actions[0].delete)
		assert.Equal(t, source.RequestKey, remove.actions[0].requestKey)
	}
}

func testSource(name string, ttl time.Duration) ProviderSource {
	target := remotehttp.FetchTarget{URL: "https://issuer.example/.well-known/openid-configuration"}
	return ProviderSource{
		OwnerKey: ProviderOwnerID{
			Kind:      OwnerKindPolicy,
			Namespace: "default",
			Name:      name,
			Path:      "spec.traffic.jwtAuthentication.providers[0].jwks.discovery",
		},
		Issuer:     "https://issuer.example",
		RequestKey: target.Key(),
		Target:     target,
		TTL:        ttl,
	}
}
