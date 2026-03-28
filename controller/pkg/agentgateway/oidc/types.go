package oidc

import (
	"crypto/tls"
	"time"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type ProviderReader interface {
	ProviderByRequestKey(requestKey remotehttp.FetchKey) (ProviderConfig, bool)
}

type ProviderConfig struct {
	RequestKey            remotehttp.FetchKey `json:"requestKey"`
	DiscoveryURL          string              `json:"discoveryUrl"`
	FetchedAt             time.Time           `json:"fetchedAt"`
	Issuer                string              `json:"issuer"`
	JwksURI               string              `json:"jwksUri"`
	AuthorizationEndpoint string              `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string              `json:"tokenEndpoint,omitempty"`
	EndSessionEndpoint    string              `json:"endSessionEndpoint,omitempty"`
}

type ProviderSource struct {
	OwnerKey   OwnerKey
	Issuer     string
	RequestKey remotehttp.FetchKey
	Target     remotehttp.FetchTarget
	TLSConfig  *tls.Config
	TTL        time.Duration
	Deleted    bool
}

func (s ProviderSource) ResourceName() string {
	return s.OwnerKey.String()
}
