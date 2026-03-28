package oidc

import (
	"encoding/json"
	"sync"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type providerCache struct {
	l         sync.RWMutex
	providers map[remotehttp.FetchKey]ProviderConfig
}

func newCache() *providerCache {
	return &providerCache{
		providers: make(map[remotehttp.FetchKey]ProviderConfig),
	}
}

func (c *providerCache) GetProvider(requestKey remotehttp.FetchKey) (ProviderConfig, bool) {
	c.l.RLock()
	defer c.l.RUnlock()

	provider, ok := c.providers[requestKey]
	return provider, ok
}

func (c *providerCache) addProvider(requestKey remotehttp.FetchKey, discoveryURL string, provider ProviderConfig) error {
	if err := ValidateProviderConfig(provider); err != nil {
		return err
	}

	serialized, err := json.Marshal(provider)
	if err != nil {
		return err
	}

	var normalized ProviderConfig
	if err := json.Unmarshal(serialized, &normalized); err != nil {
		return err
	}
	normalized.RequestKey = requestKey
	normalized.DiscoveryURL = discoveryURL

	c.l.Lock()
	defer c.l.Unlock()
	c.providers[requestKey] = normalized
	return nil
}

func (c *providerCache) deleteProvider(requestKey remotehttp.FetchKey) {
	c.l.Lock()
	defer c.l.Unlock()
	delete(c.providers, requestKey)
}
