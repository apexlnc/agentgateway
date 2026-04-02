package oidc

import (
	"errors"
	"sync"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type providerCache struct {
	mu       sync.Mutex
	provider map[remotehttp.FetchKey]ProviderConfig
}

func NewProviderCache() *providerCache {
	return &providerCache{
		provider: make(map[remotehttp.FetchKey]ProviderConfig),
	}
}

func (c *providerCache) LoadProviderConfigs(stored map[remotehttp.FetchKey]ProviderConfig) error {
	next := make(map[remotehttp.FetchKey]ProviderConfig, len(stored))
	var errs []error
	for key, cfg := range stored {
		if err := cfg.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		next[key] = cfg
	}

	c.mu.Lock()
	c.provider = next
	c.mu.Unlock()
	return errors.Join(errs...)
}

func (c *providerCache) Get(key remotehttp.FetchKey) (ProviderConfig, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg, ok := c.provider[key]
	return cfg, ok
}

func (c *providerCache) Set(key remotehttp.FetchKey, cfg ProviderConfig) {
	c.mu.Lock()
	c.provider[key] = cfg
	c.mu.Unlock()
}

func (c *providerCache) Delete(key remotehttp.FetchKey) {
	c.mu.Lock()
	delete(c.provider, key)
	c.mu.Unlock()
}
