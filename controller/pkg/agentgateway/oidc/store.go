package oidc

import (
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/common"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

const DefaultStorePrefix = "oidc-store"

var storeLogger = logging.New("oidc_store")

// Store bridges KRT-derived shared OIDC requests to the runtime that fetches,
// persists, and serves discovered providers to translation.
type Store struct {
	*remotecache.Store[SharedOidcRequest, DiscoveredProvider]
	results *OidcResults
}

func NewStore(requests krt.Collection[SharedOidcRequest], persistedEntries *PersistedEntries, storePrefix string) *Store {
	results := NewFetchedResults()
	innerStore := remotecache.NewStore(remotecache.StoreOptions[SharedOidcRequest, DiscoveredProvider]{
		Fetcher:                  NewFetcher(results),
		Requests:                 requests,
		Logger:                   storeLogger,
		Hydrator:                 persistedEntries,
		RetireOnRequestKeyChange: true,
	})

	return &Store{
		Store:   innerStore,
		results: results,
	}
}

// ProviderByRequestKey is the fetched-result view used by persistence.
// Translation reads via Lookup.ResolveForOwner (KRT-backed persisted entries)
// so xDS recomputes from Kubernetes-observed state.
func (s *Store) ProviderByRequestKey(requestKey remotehttp.FetchKey) (DiscoveredProvider, bool) {
	return s.results.Get(requestKey)
}

func (s *Store) FetchedResults() *OidcResults {
	return s.results
}

func (s *Store) RunnableName() string {
	return DefaultStorePrefix
}

var _ common.NamedRunnable = &Store{}
