package jwks

import (
	"context"

	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/util/sets"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/apiclient"
	"github.com/agentgateway/agentgateway/controller/pkg/common"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

var logger = logging.New("jwks_store")

const DefaultJwksStorePrefix = "jwks-store"
const RunnableName = "jwks-store"

// Store bridges KRT-derived shared JWKS requests to the runtime that fetches,
// persists, and serves keysets to translation.
//
// For JWT auth, JWKS is the persisted last-known-good boundary. Discovery
// metadata is resolved through the oidc subsystem at runtime, but the
// controller only persists the final key material needed by translation and
// the dataplane.
type Store struct {
	storePrefix         string
	deploymentNamespace string
	jwksCache           *jwksCache
	jwksFetcher         *fetcher
	persistedKeysets    *persistedKeysetReader
	requests            krt.Collection[SharedJwksRequest]
	ready               chan struct{}
}

func NewStore(cli apiclient.Client, krtOptions krtutil.KrtOptions, requests krt.Collection[SharedJwksRequest], providerLookup oidc.ProviderReader, storePrefix, deploymentNamespace string) *Store {
	logger.Info("creating jwks store")

	jwksCache := newCache()
	return &Store{
		storePrefix:         storePrefix,
		deploymentNamespace: deploymentNamespace,
		jwksCache:           jwksCache,
		requests:            requests,
		jwksFetcher:         newFetcherWithProviders(jwksCache, providerLookup),
		persistedKeysets:    newPersistedKeysetReader(cli, storePrefix, deploymentNamespace, krtOptions),
		ready:               make(chan struct{}),
	}
}

func (s *Store) Start(ctx context.Context) error {
	logger.Info("starting jwks store")

	storedJwks, err := s.persistedKeysets.LoadPersistedKeysets(ctx)
	if err != nil {
		logger.Error("error loading jwks store from a ConfigMap", "error", err)
	}
	if err := s.jwksCache.LoadJwksFromStores(storedJwks); err != nil {
		logger.Error("error loading jwks store state", "error", err)
	}

	registration := s.requests.Register(func(event krt.Event[SharedJwksRequest]) {
		switch event.Event {
		case controllers.EventAdd, controllers.EventUpdate:
			if event.New == nil {
				return
			}

			request := event.New.JwksSource()
			logger.Debug("updating keyset", "request_key", request.RequestKey, "config_map", JwksConfigMapName(s.storePrefix, request.RequestKey))
			if err := s.jwksFetcher.AddOrUpdateKeyset(request); err != nil {
				logger.Error("error adding/updating a jwks keyset", "error", err, "request_key", request.RequestKey, "uri", request.Target.URL)
			}
		case controllers.EventDelete:
			if event.Old == nil {
				return
			}

			logger.Debug("deleting keyset", "request_key", event.Old.RequestKey, "config_map", JwksConfigMapName(s.storePrefix, event.Old.RequestKey))
			s.jwksFetcher.RemoveKeyset(event.Old.RequestKey)
		}
	})
	defer registration.UnregisterHandler()

	go s.jwksFetcher.Run(ctx)

	if !registration.WaitUntilSynced(ctx.Done()) {
		return nil
	}
	close(s.ready)

	<-ctx.Done()
	return nil
}

func (s *Store) HasSynced() bool {
	select {
	case <-s.ready:
		return true
	default:
		return false
	}
}

func (s *Store) SubscribeToUpdates() <-chan sets.Set[remotehttp.FetchKey] {
	return s.jwksFetcher.SubscribeToUpdates()
}

func (s *Store) JwksByRequestKey(requestKey remotehttp.FetchKey) (Keyset, bool) {
	return s.jwksCache.GetJwks(requestKey)
}

func (r *Store) NeedLeaderElection() bool {
	return true
}

var _ common.NamedRunnable = &Store{}

func (r *Store) RunnableName() string {
	return RunnableName
}
