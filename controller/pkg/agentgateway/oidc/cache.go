package oidc

import (
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
)

// OidcResults stores discovered OIDC providers as a KRT-visible collection.
type OidcResults = remotecache.Results[DiscoveredProvider]

// NewResults constructs an empty OIDC result collection.
func NewResults() *OidcResults {
	return remotecache.NewResults[DiscoveredProvider]()
}
