package oidc

import (
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
)

// OidcResults stores discovered OIDC providers as a KRT-visible collection.
type OidcResults = remotecache.FetchedResults[DiscoveredProvider]

// NewFetchedResults constructs an empty OIDC fetched-result collection.
func NewFetchedResults() *OidcResults {
	return remotecache.NewFetchedResults[DiscoveredProvider]()
}
