package remotecache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil/krttest"
)

type collapseTestSource struct {
	Owner string
	Key   remotehttp.FetchKey
	TTL   time.Duration
}

type collapseTestRequest struct {
	RequestKey remotehttp.FetchKey
	Owner      string
	TTL        time.Duration
}

func TestNewSharedRequestCollectionCollapsesByFetchKey(t *testing.T) {
	krtOpts := krttest.KrtOptions(t)
	sources := krttest.NewStaticCollection(t, []collapseTestSource{
		{Owner: "z-owner", Key: "shared", TTL: 10 * time.Minute},
		{Owner: "a-owner", Key: "shared", TTL: 5 * time.Minute},
		{Owner: "other", Key: "other", TTL: 30 * time.Minute},
	}, krtOpts, "CollapseSources")

	requests := NewSharedRequestCollection(
		sources,
		"ByRequestKey",
		"GroupedRequests",
		"SharedRequests",
		krtOpts,
		func(source collapseTestSource) remotehttp.FetchKey {
			return source.Key
		},
		func(grouped krt.IndexObject[remotehttp.FetchKey, collapseTestSource]) *collapseTestRequest {
			primary, ttl := CollapseSources(grouped.Objects, func(source collapseTestSource) string {
				return source.Owner
			}, func(source collapseTestSource) time.Duration {
				return source.TTL
			})
			return &collapseTestRequest{
				RequestKey: grouped.Key,
				Owner:      primary.Owner,
				TTL:        ttl,
			}
		},
	)

	collapsed := krttest.Await(t, requests, 2)
	byKey := make(map[remotehttp.FetchKey]collapseTestRequest, len(collapsed))
	for _, request := range collapsed {
		byKey[request.RequestKey] = request
	}

	require.Contains(t, byKey, remotehttp.FetchKey("shared"))
	assert.Equal(t, "a-owner", byKey["shared"].Owner)
	assert.Equal(t, 5*time.Minute, byKey["shared"].TTL)

	require.Contains(t, byKey, remotehttp.FetchKey("other"))
	assert.Equal(t, "other", byKey["other"].Owner)
}

func TestCollapseSourcesUsesStableOwnerOrderingAndMinTTL(t *testing.T) {
	primary, ttl := CollapseSources([]collapseTestSource{
		{Owner: "z-owner", TTL: 20 * time.Minute},
		{Owner: "a-owner", TTL: 5 * time.Minute},
		{Owner: "m-owner", TTL: 10 * time.Minute},
	}, func(source collapseTestSource) string {
		return source.Owner
	}, func(source collapseTestSource) time.Duration {
		return source.TTL
	})

	assert.Equal(t, "a-owner", primary.Owner)
	assert.Equal(t, 5*time.Minute, ttl)
}

func TestNewSharedRequestCollectionRecomputesOnSourceReset(t *testing.T) {
	krtOpts := krttest.KrtOptions(t)
	sources := krttest.NewStaticCollection(t, []collapseTestSource{
		{Owner: "owner-a", Key: "shared", TTL: 5 * time.Minute},
	}, krtOpts, "DynamicSources")

	requests := NewSharedRequestCollection(
		sources,
		"ByRequestKey",
		"GroupedRequests",
		"SharedRequests",
		krtOpts,
		func(source collapseTestSource) remotehttp.FetchKey {
			return source.Key
		},
		func(grouped krt.IndexObject[remotehttp.FetchKey, collapseTestSource]) *collapseTestRequest {
			primary, ttl := CollapseSources(grouped.Objects, func(source collapseTestSource) string {
				return source.Owner
			}, func(source collapseTestSource) time.Duration {
				return source.TTL
			})
			return &collapseTestRequest{
				RequestKey: grouped.Key,
				Owner:      primary.Owner,
				TTL:        ttl,
			}
		},
	)

	initial := krttest.Await(t, requests, 1)
	assert.Equal(t, "owner-a", initial[0].Owner)

	sources.Reset([]collapseTestSource{
		{Owner: "owner-b", Key: "shared", TTL: 1 * time.Minute},
	})

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		updated := krttest.Await(t, requests, 1)
		assert.Equal(c, "owner-b", updated[0].Owner)
		assert.Equal(c, 1*time.Minute, updated[0].TTL)
	}, krttest.EventuallyTimeout, krttest.EventuallyPoll)
}

var _ krt.ResourceNamer = collapseTestRequest{}

func (c collapseTestRequest) ResourceName() string {
	return string(c.RequestKey)
}
