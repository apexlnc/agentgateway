package oidc

import (
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/common"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

const DefaultStorePrefix = "oidc-store"

var logger = logging.New("agentgateway/oidc")

// OidcResults stores discovered OIDC providers as a KRT-visible collection.
type OidcResults = remotecache.FetchedResults[DiscoveredProvider]

// NewFetchedResults constructs an empty OIDC fetched-result collection.
func NewFetchedResults() *OidcResults {
	return remotecache.NewFetchedResults[DiscoveredProvider]()
}

// Store bridges KRT-derived shared OIDC requests to the runtime that fetches,
// persists, and serves discovered providers to translation.
type Store struct {
	*remotecache.Store[SharedOidcRequest, DiscoveredProvider]
	// Driver is the OIDC HTTP fetch driver. Exposed so tests can swap its
	// DefaultClient for an offline transport.
	Driver  *OidcDriver
	results *OidcResults
}

func NewStore(requests krt.Collection[SharedOidcRequest], persistedEntries *PersistedEntries, storePrefix string) *Store {
	results := NewFetchedResults()
	fetcher, driver := NewFetcher(results)
	innerStore := remotecache.NewStore(remotecache.StoreOptions[SharedOidcRequest, DiscoveredProvider]{
		Fetcher:  fetcher,
		Requests: requests,
		Logger:   logger,
		Hydrate:  persistedEntries.LoadAll,
	})

	return &Store{
		Store:   innerStore,
		Driver:  driver,
		results: results,
	}
}

// ProviderByRequestKey returns the cached provider for the given request key,
// or false if absent. Test-only: production reads through FetchedResults().
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
