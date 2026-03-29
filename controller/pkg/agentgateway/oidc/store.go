package oidc

import (
	"context"

	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/common"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

var logger = logging.New("oidc_store")

const RunnableName = "oidc-store"

// Store bridges KRT-derived shared discovery requests to the concrete runtime
// that fetches and caches provider metadata for downstream consumers.
//
// Provider metadata is intentionally runtime-only here: for the current JWT
// flow, JWKS remains the durable last-known-good artifact and is persisted by
// the jwks subsystem. OIDC stays separate so other controller-side OIDC
// consumers can reuse discovery without depending on JWKS internals.
type Store struct {
	providerCache   *providerCache
	providerFetcher *fetcher
	requests        krt.Collection[SharedProviderRequest]
	ready           chan struct{}
}

func NewStore(requests krt.Collection[SharedProviderRequest]) *Store {
	logger.Info("creating oidc store")

	providerCache := newCache()
	return &Store{
		providerCache:   providerCache,
		providerFetcher: newFetcher(providerCache),
		requests:        requests,
		ready:           make(chan struct{}),
	}
}

func (s *Store) Start(ctx context.Context) error {
	logger.Info("starting oidc store")

	registration := s.requests.Register(func(event krt.Event[SharedProviderRequest]) {
		switch event.Event {
		case controllers.EventAdd, controllers.EventUpdate:
			if event.New == nil {
				return
			}

			request := event.New.ProviderSource()
			logger.Debug("updating oidc provider metadata", "request_key", request.RequestKey)
			if err := s.providerFetcher.AddOrUpdateProvider(request); err != nil {
				logger.Error("error adding/updating oidc provider metadata", "error", err, "request_key", request.RequestKey, "url", request.Target.URL)
			}
		case controllers.EventDelete:
			if event.Old == nil {
				return
			}

			logger.Debug("deleting oidc provider metadata", "request_key", event.Old.RequestKey)
			s.providerFetcher.RemoveProvider(event.Old.RequestKey)
		}
	})
	defer registration.UnregisterHandler()

	go s.providerFetcher.Run(ctx)

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

func (s *Store) ProviderByRequestKey(requestKey remotehttp.FetchKey) (ProviderConfig, bool) {
	return s.providerCache.GetProvider(requestKey)
}

func (s *Store) NeedLeaderElection() bool {
	return true
}

func (s *Store) RunnableName() string {
	return RunnableName
}

var _ common.NamedRunnable = &Store{}
