package jwks

import (
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/common"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

const DefaultJwksStorePrefix = "jwks-store"

var storeLogger = logging.New("jwks_store")

// JwksResults stores fetched JWKS keysets as a KRT-visible collection.
type JwksResults = remotecache.FetchedResults[Keyset]

// NewFetchedResults constructs an empty JWKS fetched-result collection.
func NewFetchedResults() *JwksResults {
	return remotecache.NewFetchedResults[Keyset]()
}

// Store bridges KRT-derived shared JWKS requests to the runtime that fetches,
// persists, and serves keysets to translation.
type Store struct {
	*remotecache.Store[SharedJwksRequest, Keyset]
	// Driver is the JWKS HTTP fetch driver. Exposed so tests can swap its
	// DefaultClient for an offline transport.
	Driver  *JwksDriver
	results *JwksResults
}

func NewStore(requests krt.Collection[SharedJwksRequest], persistedEntries *PersistedEntries, storePrefix string) *Store {
	results := NewFetchedResults()
	fetcher, driver := NewFetcher(results)
	innerStore := remotecache.NewStore(remotecache.StoreOptions[SharedJwksRequest, Keyset]{
		Fetcher:  fetcher,
		Requests: requests,
		Logger:   storeLogger,
		Hydrate:  persistedEntries.LoadAll,
	})

	return &Store{
		Store:   innerStore,
		Driver:  driver,
		results: results,
	}
}

func (s *Store) JwksByRequestKey(requestKey remotehttp.FetchKey) (Keyset, bool) {
	return s.results.Get(requestKey)
}

func (s *Store) FetchedResults() *JwksResults {
	return s.results
}

func (s *Store) RunnableName() string {
	return DefaultJwksStorePrefix
}

var _ common.NamedRunnable = &Store{}
