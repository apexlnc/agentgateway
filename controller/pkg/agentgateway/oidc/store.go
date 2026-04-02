package oidc

import (
	"context"
	"sync"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/apiclient"
	"github.com/agentgateway/agentgateway/controller/pkg/common"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

var logger = logging.New("oidc_store")

type OIDCStore struct {
	providerStorePrefix string
	providerCache       *providerCache
	providerFetcher     *ProviderFetcher
	configMapSyncer     *configMapSyncer
	sourceChanges       <-chan ProviderSource

	mu             sync.Mutex
	ownerToSource  map[OwnerKey]ProviderSource
	requestToOwner map[remotehttp.FetchKey]map[OwnerKey]struct{}
}

func BuildOIDCStore(
	cli apiclient.Client,
	krtOpts krtutil.KrtOptions,
	sourceChanges <-chan ProviderSource,
	providerStorePrefix, deploymentNamespace string,
) *OIDCStore {
	cache := NewProviderCache()
	return &OIDCStore{
		providerStorePrefix: providerStorePrefix,
		providerCache:       cache,
		providerFetcher:     NewProviderFetcher(cache),
		configMapSyncer:     NewConfigMapSyncer(cli, providerStorePrefix, deploymentNamespace, krtOpts),
		sourceChanges:       sourceChanges,
		ownerToSource:       make(map[OwnerKey]ProviderSource),
		requestToOwner:      make(map[remotehttp.FetchKey]map[OwnerKey]struct{}),
	}
}

func (s *OIDCStore) Start(ctx context.Context) error {
	logger.Info("starting oidc store")

	storedProviders, err := s.configMapSyncer.LoadProviderConfigs(ctx)
	if err != nil {
		logger.Error("error loading oidc provider store from ConfigMaps", "error", err)
	}
	if err := s.providerCache.LoadProviderConfigs(storedProviders); err != nil {
		logger.Error("error loading oidc provider cache", "error", err)
	}

	go s.providerFetcher.Run(ctx)
	go s.updateSources(ctx)

	<-ctx.Done()
	return nil
}

func (s *OIDCStore) SubscribeToProviderUpdates() chan map[remotehttp.FetchKey]struct{} {
	return s.providerFetcher.SubscribeToUpdates()
}

func (s *OIDCStore) ProviderByConfigMapName(name string) (remotehttp.FetchKey, ProviderConfig, bool) {
	prefix := s.providerStorePrefix + "-"
	if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
		return "", ProviderConfig{}, false
	}
	key := remotehttp.FetchKey(name[len(prefix):])
	cfg, ok := s.providerCache.Get(key)
	return key, cfg, ok
}

func (s *OIDCStore) updateSources(ctx context.Context) {
	for {
		select {
		case source := <-s.sourceChanges:
			s.handleSourceChange(source)
		case <-ctx.Done():
			return
		}
	}
}

func (s *OIDCStore) handleSourceChange(source ProviderSource) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if oldSource, ok := s.ownerToSource[source.OwnerKey]; ok && oldSource.RequestKey != source.RequestKey {
		s.detachOwnerLocked(source.OwnerKey, oldSource.RequestKey)
	}

	if source.Deleted {
		if oldSource, ok := s.ownerToSource[source.OwnerKey]; ok {
			s.detachOwnerLocked(source.OwnerKey, oldSource.RequestKey)
		}
		return
	}

	s.ownerToSource[source.OwnerKey] = source
	owners := s.requestToOwner[source.RequestKey]
	if owners == nil {
		owners = map[OwnerKey]struct{}{}
		s.requestToOwner[source.RequestKey] = owners
	}
	owners[source.OwnerKey] = struct{}{}

	s.syncSharedSourceLocked(source.RequestKey)
}

func (s *OIDCStore) detachOwnerLocked(owner OwnerKey, requestKey remotehttp.FetchKey) {
	delete(s.ownerToSource, owner)

	owners := s.requestToOwner[requestKey]
	if owners == nil {
		return
	}
	delete(owners, owner)
	if len(owners) != 0 {
		s.syncSharedSourceLocked(requestKey)
		return
	}

	delete(s.requestToOwner, requestKey)
	s.providerFetcher.RemoveSource(ProviderSource{OwnerKey: owner, RequestKey: requestKey})
}

func (s *OIDCStore) syncSharedSourceLocked(requestKey remotehttp.FetchKey) {
	source, ok := s.sharedSourceLocked(requestKey)
	if !ok {
		return
	}
	if err := s.providerFetcher.AddOrUpdateSource(source); err != nil {
		logger.Error("error adding/updating oidc provider source", "error", err, "owner", source.OwnerKey, "request_key", source.RequestKey)
	}
}

func (s *OIDCStore) sharedSourceLocked(requestKey remotehttp.FetchKey) (ProviderSource, bool) {
	owners := s.requestToOwner[requestKey]
	if len(owners) == 0 {
		return ProviderSource{}, false
	}

	var shared ProviderSource
	var found bool
	for owner := range owners {
		source, ok := s.ownerToSource[owner]
		if !ok {
			continue
		}
		if !found {
			shared = source
			found = true
			continue
		}
		if source.TTL < shared.TTL {
			shared.TTL = source.TTL
		}
	}

	return shared, found
}

func (s *OIDCStore) NeedLeaderElection() bool {
	return true
}

func (s *OIDCStore) RunnableName() string {
	return RunnableName
}

var _ common.NamedRunnable = (*OIDCStore)(nil)
