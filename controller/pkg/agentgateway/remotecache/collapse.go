package remotecache

import (
	"cmp"
	"time"

	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/slices"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

// CollapseSources merges per-owner sources sharing a fetch key into a single
// canonical record. It returns the source with the lowest ownerKey (so output
// is stable across input order) and the minimum TTL across all sources (so
// the shared fetch refreshes as often as the most aggressive owner requires).
//
// Callers must pre-filter empty input — CollapseSources panics on len 0.
func CollapseSources[S any](sources []S, ownerKey func(S) string, ttl func(S) time.Duration) (S, time.Duration) {
	sorted := append([]S(nil), sources...)
	slices.SortFunc(sorted, func(a, b S) int {
		return cmp.Compare(ownerKey(a), ownerKey(b))
	})
	primary := sorted[0]
	minTTL := ttl(primary)
	for _, s := range sorted[1:] {
		if t := ttl(s); t < minTTL {
			minTTL = t
		}
	}
	return primary, minTTL
}

// SharedRequests groups per-owner sources by FetchKey and collapses each group
// into the single request the remote fetch runtime should manage. This captures
// the standard KRT graph used by JWKS and OIDC:
//
//     source collection -> request-key index -> grouped index collection -> request collection
//
// Subsystems keep only the domain-specific source production and collapse
// semantics, while the KRT grouping pipeline stays shared and idiomatic.
func SharedRequests[S any, R any](
	sources krt.Collection[S],
	indexName string,
	groupsName string,
	requestsName string,
	krtOpts krtutil.KrtOptions,
	requestKey func(S) remotehttp.FetchKey,
	collapse func(krt.IndexObject[remotehttp.FetchKey, S]) *R,
) krt.Collection[R] {
	byRequestKey := krt.NewIndex(sources, indexName, func(source S) []remotehttp.FetchKey {
		return []remotehttp.FetchKey{requestKey(source)}
	})
	groups := byRequestKey.AsCollection(append(krtOpts.ToOptions(groupsName), FetchKeyIndexCollectionOption)...)
	return krt.NewCollection(groups, func(kctx krt.HandlerContext, grouped krt.IndexObject[remotehttp.FetchKey, S]) *R {
		return collapse(grouped)
	}, krtOpts.ToOptions(requestsName)...)
}
