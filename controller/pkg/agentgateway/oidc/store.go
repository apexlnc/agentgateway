package oidc

import (
	"context"
	"sync"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/common"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

var logger = logging.New("oidc_store")

const RunnableName = "oidc-store"

type Store struct {
	providerCache      *providerCache
	providerFetcher    *fetcher
	providerChanges    <-chan ProviderSource
	sourcesByOwner     map[OwnerKey]ProviderSource
	ownersByRequestKey map[remotehttp.FetchKey]map[OwnerKey]ProviderSource
	l                  sync.Mutex
	ready              chan struct{}
}

type storeUpdate struct {
	actions []providerRequestAction
}

type providerRequestAction struct {
	requestKey remotehttp.FetchKey
	upsert     *ProviderSource
	delete     bool
}

func NewStore(providerChanges <-chan ProviderSource) *Store {
	logger.Info("creating oidc store")

	providerCache := newCache()
	return &Store{
		providerCache:      providerCache,
		providerFetcher:    newFetcher(providerCache),
		providerChanges:    providerChanges,
		sourcesByOwner:     make(map[OwnerKey]ProviderSource),
		ownersByRequestKey: make(map[remotehttp.FetchKey]map[OwnerKey]ProviderSource),
		ready:              make(chan struct{}),
	}
}

func (s *Store) Start(ctx context.Context) error {
	logger.Info("starting oidc store")
	close(s.ready)

	go s.providerFetcher.Run(ctx)
	go s.updateProviders(ctx)

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

func (s *Store) updateProviders(ctx context.Context) {
	for {
		select {
		case providerUpdate := <-s.providerChanges:
			var update storeUpdate
			if providerUpdate.Deleted {
				update = s.removeOwner(providerUpdate.OwnerKey)
			} else {
				update = s.applyOwnerUpdate(providerUpdate)
			}

			s.applyProviderActions(update.actions)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Store) applyProviderActions(actions []providerRequestAction) {
	for _, action := range actions {
		if action.delete {
			logger.Debug("deleting oidc provider metadata", "request_key", action.requestKey)
			s.providerFetcher.RemoveProvider(action.requestKey)
			continue
		}
		if action.upsert == nil {
			continue
		}

		logger.Debug("updating oidc provider metadata", "request_key", action.upsert.RequestKey)
		if err := s.providerFetcher.AddOrUpdateProvider(*action.upsert); err != nil {
			logger.Error("error adding/updating oidc provider metadata", "error", err, "request_key", action.upsert.RequestKey, "url", action.upsert.Target.URL)
		}
	}
}

func (s *Store) applyOwnerUpdate(source ProviderSource) storeUpdate {
	s.l.Lock()
	defer s.l.Unlock()

	update := storeUpdate{
		actions: make([]providerRequestAction, 0, 2),
	}

	if existing, ok := s.sourcesByOwner[source.OwnerKey]; ok && existing.RequestKey != source.RequestKey {
		s.deleteOwnerLocked(existing.OwnerKey, existing.RequestKey)
		update.actions = append(update.actions, s.reconcileRequestLocked(existing.RequestKey))
	}

	s.sourcesByOwner[source.OwnerKey] = source
	owners := s.ownersByRequestKey[source.RequestKey]
	if owners == nil {
		owners = make(map[OwnerKey]ProviderSource)
		s.ownersByRequestKey[source.RequestKey] = owners
	}
	owners[source.OwnerKey] = source

	update.actions = append(update.actions, s.reconcileRequestLocked(source.RequestKey))

	return update
}

func (s *Store) removeOwner(ownerKey OwnerKey) storeUpdate {
	s.l.Lock()
	defer s.l.Unlock()

	existing, ok := s.sourcesByOwner[ownerKey]
	if !ok {
		return storeUpdate{}
	}

	s.deleteOwnerLocked(ownerKey, existing.RequestKey)
	update := storeUpdate{
		actions: []providerRequestAction{s.reconcileRequestLocked(existing.RequestKey)},
	}
	return update
}

func (s *Store) deleteOwnerLocked(ownerKey OwnerKey, requestKey remotehttp.FetchKey) {
	delete(s.sourcesByOwner, ownerKey)
	owners := s.ownersByRequestKey[requestKey]
	delete(owners, ownerKey)
	if len(owners) == 0 {
		delete(s.ownersByRequestKey, requestKey)
	}
}

func (s *Store) reconcileRequestLocked(requestKey remotehttp.FetchKey) providerRequestAction {
	owners := s.ownersByRequestKey[requestKey]
	if len(owners) == 0 {
		return providerRequestAction{requestKey: requestKey, delete: true}
	}

	shared := sharedSource(owners)
	return providerRequestAction{requestKey: requestKey, upsert: &shared}
}

func sharedSource(owners map[OwnerKey]ProviderSource) ProviderSource {
	var (
		shared ProviderSource
		first  = true
	)

	for _, source := range owners {
		if first {
			shared = source
			first = false
			continue
		}
		if source.TTL < shared.TTL {
			shared.TTL = source.TTL
		}
	}

	return shared
}

func (s *Store) NeedLeaderElection() bool {
	return true
}

func (s *Store) RunnableName() string {
	return RunnableName
}

var _ common.NamedRunnable = &Store{}
