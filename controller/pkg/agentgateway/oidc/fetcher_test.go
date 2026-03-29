package oidc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

const (
	testEventuallyTimeout = 2 * time.Second
	testEventuallyPoll    = 20 * time.Millisecond
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

	provider := awaitProviderConfig(t, f.cache, source.RequestKey)
	assert.Equal(t, source.Issuer, provider.Issuer)
	assert.Equal(t, "https://issuer.example/keys", provider.JwksURI)
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

	awaitNoProviderConfig(t, f.cache, source.RequestKey)
	retry := awaitProviderRetryAttempt(t, f, source.RequestKey, 1)
	assert.WithinDuration(t, time.Now().Add(200*time.Millisecond), retry.at, 2*time.Second)
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

	awaitNoProviderConfig(t, f.cache, source.RequestKey)
	awaitProviderRetryAttempt(t, f, source.RequestKey, 1)
}

func awaitProviderConfig(t *testing.T, cache *providerCache, requestKey remotehttp.FetchKey) ProviderConfig {
	t.Helper()

	var provider ProviderConfig
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var ok bool
		provider, ok = cache.GetProvider(requestKey)
		assert.True(c, ok)
	}, testEventuallyTimeout, testEventuallyPoll)

	return provider
}

func awaitNoProviderConfig(t *testing.T, cache *providerCache, requestKey remotehttp.FetchKey) {
	t.Helper()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, ok := cache.GetProvider(requestKey)
		assert.False(c, ok)
	}, testEventuallyTimeout, testEventuallyPoll)
}

func awaitProviderRetryAttempt(t *testing.T, f *fetcher, requestKey remotehttp.FetchKey, retryAttempt int) fetchAt {
	t.Helper()

	var retry fetchAt
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		retry = awaitProviderRetryNoWait(f)
		assert.Equal(c, requestKey, retry.requestKey)
		assert.Equal(c, retryAttempt, retry.retryAttempt)
	}, testEventuallyTimeout, testEventuallyPoll)

	return retry
}

func awaitProviderRetryNoWait(f *fetcher) fetchAt {
	f.mu.Lock()
	defer f.mu.Unlock()

	scheduled := f.schedule.Peek()
	if scheduled == nil {
		return fetchAt{}
	}
	return *scheduled
}
