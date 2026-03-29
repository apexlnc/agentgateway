package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/kube/krt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/shared"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

func TestSharedProviderRequestsCollapseMinTTLAcrossOwners(t *testing.T) {
	krtOpts := testKrtOptions(t)
	policies := krt.NewStaticCollection(alwaysSynced{}, []*agentgateway.AgentgatewayPolicy{
		testPolicy("one", "https://issuer.example", 5*time.Minute),
		testPolicy("two", "https://issuer.example", 2*time.Minute),
	})

	collections := NewCollections(CollectionInputs{
		AgentgatewayPolicies: policies,
		Resolver: providerResolverFunc(func(owner ProviderOwner) (*ResolvedProviderRequest, error) {
			return resolvedProviderRequest(owner, "https://idp.internal/.well-known/openid-configuration"), nil
		}),
		KrtOpts: krtOpts,
	})

	requests := awaitSharedProviderRequests(t, collections.SharedRequests, 1)
	assert.Equal(t, remotehttp.FetchTarget{URL: "https://idp.internal/.well-known/openid-configuration"}.Key(), requests[0].RequestKey)
	assert.Equal(t, 2*time.Minute, requests[0].TTL)
	assert.Equal(t, "https://issuer.example", requests[0].Issuer)
}

func TestSharedProviderRequestsRetargetOwnerAcrossRequestKeys(t *testing.T) {
	krtOpts := testKrtOptions(t)
	policies := dynamicPolicies(t, []*agentgateway.AgentgatewayPolicy{
		testPolicy("moving", "https://issuer.example/a", 5*time.Minute),
		testPolicy("staying", "https://issuer.example/a", 10*time.Minute),
	}, krtOpts)

	collections := NewCollections(CollectionInputs{
		AgentgatewayPolicies: policies,
		Resolver: providerResolverFunc(func(owner ProviderOwner) (*ResolvedProviderRequest, error) {
			switch owner.Issuer {
			case "https://issuer.example/a":
				return resolvedProviderRequest(owner, "https://idp.internal/a/.well-known/openid-configuration"), nil
			case "https://issuer.example/b":
				return resolvedProviderRequest(owner, "https://idp.internal/b/.well-known/openid-configuration"), nil
			default:
				return nil, assert.AnError
			}
		}),
		KrtOpts: krtOpts,
	})

	requests := awaitSharedProviderRequests(t, collections.SharedRequests, 1)
	assert.Equal(t, 5*time.Minute, requests[0].TTL)

	updatedPolicies := []*agentgateway.AgentgatewayPolicy{
		testPolicy("moving", "https://issuer.example/b", 5*time.Minute),
		testPolicy("staying", "https://issuer.example/a", 10*time.Minute),
	}
	policies.Reset(updatedPolicies)

	requestsByKey := requestsByKey(awaitSharedProviderRequests(t, collections.SharedRequests, 2))
	assert.Equal(t, 10*time.Minute, requestsByKey[remotehttp.FetchTarget{URL: "https://idp.internal/a/.well-known/openid-configuration"}.Key()].TTL)
	assert.Equal(t, 5*time.Minute, requestsByKey[remotehttp.FetchTarget{URL: "https://idp.internal/b/.well-known/openid-configuration"}.Key()].TTL)
}

func TestSharedProviderRequestsRemoveLastOwnerDeletesRequest(t *testing.T) {
	krtOpts := testKrtOptions(t)
	policies := dynamicPolicies(t, []*agentgateway.AgentgatewayPolicy{
		testPolicy("one", "https://issuer.example", 5*time.Minute),
	}, krtOpts)

	collections := NewCollections(CollectionInputs{
		AgentgatewayPolicies: policies,
		Resolver: providerResolverFunc(func(owner ProviderOwner) (*ResolvedProviderRequest, error) {
			return resolvedProviderRequest(owner, "https://idp.internal/.well-known/openid-configuration"), nil
		}),
		KrtOpts: krtOpts,
	})

	awaitSharedProviderRequests(t, collections.SharedRequests, 1)

	policies.Reset(nil)

	awaitSharedProviderRequests(t, collections.SharedRequests, 0)
}

func TestStoreTracksSharedRequestCollectionLifecycle(t *testing.T) {
	krtOpts := testKrtOptions(t)
	requests := dynamicSharedProviderRequests(t, []SharedProviderRequest{
		testSharedProviderRequest("https://idp.internal/a/.well-known/openid-configuration", "https://issuer.example/a", 5*time.Minute),
	}, krtOpts)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	store := NewStore(requests)
	go func() {
		_ = store.Start(ctx)
	}()

	assert.Eventually(t, store.HasSynced, testEventuallyTimeout, testEventuallyPoll)
	state := awaitProviderFetchState(t, store.providerFetcher, remotehttp.FetchTarget{URL: "https://idp.internal/a/.well-known/openid-configuration"}.Key())
	assert.Equal(t, 5*time.Minute, state.source.TTL)

	updatedRequests := []SharedProviderRequest{
		testSharedProviderRequest("https://idp.internal/b/.well-known/openid-configuration", "https://issuer.example/b", 10*time.Minute),
	}
	requests.Reset(updatedRequests)

	awaitNoProviderFetchState(t, store.providerFetcher, remotehttp.FetchTarget{URL: "https://idp.internal/a/.well-known/openid-configuration"}.Key())
	newState := awaitProviderFetchState(t, store.providerFetcher, remotehttp.FetchTarget{URL: "https://idp.internal/b/.well-known/openid-configuration"}.Key())
	assert.Equal(t, 10*time.Minute, newState.source.TTL)

	requests.Reset(nil)

	awaitNoProviderFetchState(t, store.providerFetcher, remotehttp.FetchTarget{URL: "https://idp.internal/b/.well-known/openid-configuration"}.Key())
}

func TestStoreHasSyncedReflectsReadyState(t *testing.T) {
	store := &Store{
		ready: make(chan struct{}),
	}

	assert.False(t, store.HasSynced())

	close(store.ready)

	assert.True(t, store.HasSynced())
}

type providerResolverFunc func(owner ProviderOwner) (*ResolvedProviderRequest, error)

func (f providerResolverFunc) ResolveOwner(_ krt.HandlerContext, owner ProviderOwner) (*ResolvedProviderRequest, error) {
	return f(owner)
}

type alwaysSynced struct{}

func (alwaysSynced) WaitUntilSynced(stop <-chan struct{}) bool {
	return true
}

func (alwaysSynced) HasSynced() bool {
	return true
}

func testKrtOptions(t *testing.T) krtutil.KrtOptions {
	t.Helper()
	return krtutil.NewKrtOptions(t.Context().Done(), new(krt.DebugHandler))
}

func testPolicy(name, issuer string, ttl time.Duration) *agentgateway.AgentgatewayPolicy {
	return &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      name,
		},
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs: make([]shared.LocalPolicyTargetReferenceWithSectionName, 1),
			Traffic: &agentgateway.Traffic{
				JWTAuthentication: &agentgateway.JWTAuthentication{
					Providers: []agentgateway.JWTProvider{{
						Issuer: issuer,
						JWKS: agentgateway.JWKS{
							Discovery: &agentgateway.OIDCDiscovery{
								CacheDuration: &metav1.Duration{Duration: ttl},
							},
						},
					}},
				},
			},
		},
	}
}

func dynamicPolicies(
	t *testing.T,
	initial []*agentgateway.AgentgatewayPolicy,
	krtOpts krtutil.KrtOptions,
) krt.StaticCollection[*agentgateway.AgentgatewayPolicy] {
	t.Helper()

	return krt.NewStaticCollection(alwaysSynced{}, initial, krtOpts.ToOptions("ProviderPolicies")...)
}

func dynamicSharedProviderRequests(
	t *testing.T,
	initial []SharedProviderRequest,
	krtOpts krtutil.KrtOptions,
) krt.StaticCollection[SharedProviderRequest] {
	t.Helper()

	return krt.NewStaticCollection(alwaysSynced{}, initial, krtOpts.ToOptions("SharedProviderRequestsInput")...)
}

func resolvedProviderRequest(owner ProviderOwner, requestURL string) *ResolvedProviderRequest {
	target := remotehttp.FetchTarget{URL: requestURL}
	return &ResolvedProviderRequest{
		OwnerID: owner.ID,
		Issuer:  owner.Issuer,
		Target: remotehttp.ResolvedTarget{
			Key:    target.Key(),
			Target: target,
		},
		TTL: owner.TTL,
	}
}

func testSharedProviderRequest(requestURL, issuer string, ttl time.Duration) SharedProviderRequest {
	target := remotehttp.FetchTarget{URL: requestURL}
	return SharedProviderRequest{
		RequestKey: target.Key(),
		Issuer:     issuer,
		Target:     target,
		TTL:        ttl,
	}
}

func requestsByKey(requests []SharedProviderRequest) map[remotehttp.FetchKey]SharedProviderRequest {
	out := make(map[remotehttp.FetchKey]SharedProviderRequest, len(requests))
	for _, request := range requests {
		out[request.RequestKey] = request
	}
	return out
}

func awaitProviderFetchState(t *testing.T, f *fetcher, requestKey remotehttp.FetchKey) fetchState {
	t.Helper()

	var state fetchState
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var ok bool
		state, ok = f.lookup(requestKey)
		assert.True(c, ok)
	}, testEventuallyTimeout, testEventuallyPoll)

	return state
}

func awaitNoProviderFetchState(t *testing.T, f *fetcher, requestKey remotehttp.FetchKey) {
	t.Helper()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, ok := f.lookup(requestKey)
		assert.False(c, ok)
	}, testEventuallyTimeout, testEventuallyPoll)
}

func awaitSharedProviderRequests(t *testing.T, requests krt.Collection[SharedProviderRequest], expectedLen int) []SharedProviderRequest {
	t.Helper()

	var shared []SharedProviderRequest
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		shared = requests.List()
		assert.Len(c, shared, expectedLen)
	}, testEventuallyTimeout, testEventuallyPoll)

	return shared
}
