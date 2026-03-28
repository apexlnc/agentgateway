package oidc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

func TestFetcherStoresProviderConfigAfterSuccessfulFetch(t *testing.T) {
	ctx := t.Context()
	source := testProviderSource("https://issuer.example")

	f := newFetcher(newCache())
	assert.NoError(t, f.AddOrUpdateProvider(source))
	f.defaultProviderClient = stubProviderClient{
		t:           t,
		expectedReq: source.Target,
		result: ProviderConfig{
			Issuer:  source.Issuer,
			JwksURI: "https://issuer.example/keys",
		},
	}

	go f.maybeFetchProviderConfig(ctx)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		provider, ok := f.cache.GetProvider(source.RequestKey)
		assert.True(c, ok)
		assert.Equal(c, source.Issuer, provider.Issuer)
		assert.Equal(c, "https://issuer.example/keys", provider.JwksURI)
	}, 2*time.Second, 100*time.Millisecond)
}

func TestFetcherRejectsIssuerMismatchBeforeCaching(t *testing.T) {
	ctx := t.Context()
	source := testProviderSource("https://issuer.example")

	f := newFetcher(newCache())
	assert.NoError(t, f.AddOrUpdateProvider(source))
	f.defaultProviderClient = stubProviderClient{
		t:           t,
		expectedReq: source.Target,
		result: ProviderConfig{
			Issuer:  "https://other.example",
			JwksURI: "https://other.example/keys",
		},
	}

	go f.maybeFetchProviderConfig(ctx)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, ok := f.cache.GetProvider(source.RequestKey)
		assert.False(c, ok)
		f.mu.Lock()
		defer f.mu.Unlock()
		retry := f.schedule.Peek()
		assert.NotNil(c, retry)
		assert.WithinDuration(c, time.Now().Add(200*time.Millisecond), retry.at, 2*time.Second)
		assert.Equal(c, 1, retry.retryAttempt)
		assert.Equal(c, source.RequestKey, retry.requestKey)
	}, 2*time.Second, 100*time.Millisecond)
}

func testProviderSource(issuer string) ProviderSource {
	target := remotehttp.FetchTarget{URL: "https://idp.internal/.well-known/openid-configuration"}
	return ProviderSource{
		OwnerKey: ProviderOwnerID{
			Kind:      OwnerKindPolicy,
			Namespace: "default",
			Name:      "policy",
			Path:      "spec.traffic.jwtAuthentication.providers[0].jwks.discovery",
		},
		Issuer:     issuer,
		RequestKey: target.Key(),
		Target:     target,
		TTL:        5 * time.Minute,
	}
}

type stubProviderClient struct {
	t           *testing.T
	expectedReq remotehttp.FetchTarget
	result      ProviderConfig
	err         error
}

func (s stubProviderClient) FetchProviderConfig(_ context.Context, target remotehttp.FetchTarget) (ProviderConfig, error) {
	assert.Equal(s.t, s.expectedReq, target)
	if s.err != nil {
		return ProviderConfig{}, s.err
	}
	return s.result, nil
}

func TestFetcherRetriesWhenProviderFetchFails(t *testing.T) {
	ctx := t.Context()
	source := testProviderSource("https://issuer.example")

	f := newFetcher(newCache())
	assert.NoError(t, f.AddOrUpdateProvider(source))
	f.defaultProviderClient = stubProviderClient{
		t:           t,
		expectedReq: source.Target,
		err:         fmt.Errorf("boom"),
	}

	go f.maybeFetchProviderConfig(ctx)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, ok := f.cache.GetProvider(source.RequestKey)
		assert.False(c, ok)
		f.mu.Lock()
		defer f.mu.Unlock()
		retry := f.schedule.Peek()
		assert.NotNil(c, retry)
		assert.Equal(c, 1, retry.retryAttempt)
		assert.Equal(c, source.RequestKey, retry.requestKey)
	}, 2*time.Second, 100*time.Millisecond)
}
