package jwks

import (
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/common"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

const DefaultJwksStorePrefix = "jwks-store"
const RunnableName = "jwks-store"

var storeLogger = logging.New("jwks_store")

// Store bridges KRT-derived shared JWKS requests to the runtime that fetches,
// persists, and serves keysets to translation.
type Store struct {
	*remotecache.Store[SharedJwksRequest, Keyset]
	results *JwksResults
}

func NewStore(requests krt.Collection[SharedJwksRequest], persistedEntries *PersistedEntries, storePrefix string) *Store {
	results := NewResults()
	innerStore := remotecache.NewStore(remotecache.StoreOptions[SharedJwksRequest, Keyset]{
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

func (s *Store) JwksByRequestKey(requestKey remotehttp.FetchKey) (Keyset, bool) {
	return s.results.Get(requestKey)
}

func (s *Store) Results() *JwksResults {
	return s.results
}

func (s *Store) RunnableName() string {
	return RunnableName
}

var _ common.NamedRunnable = &Store{}
