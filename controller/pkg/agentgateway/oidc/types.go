package oidc

import (
	"crypto/tls"
	"reflect"
	"time"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// ProviderReader exposes last-known provider metadata by request key to
// downstream consumers such as jwks while keeping discovery as a separate
// controller-side subsystem from key materialization.
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

// ProviderSource is a per-owner discovery request before KRT collapses
// equivalent sources onto a shared request key.
type ProviderSource struct {
	OwnerKey   OwnerKey
	Issuer     string
	RequestKey remotehttp.FetchKey
	Target     remotehttp.FetchTarget
	// +noKrtEquals
	TLSConfig *tls.Config
	TTL       time.Duration
}

func (s ProviderSource) ResourceName() string {
	return s.OwnerKey.String()
}

func (s ProviderSource) Equals(other ProviderSource) bool {
	return s.OwnerKey == other.OwnerKey &&
		s.Issuer == other.Issuer &&
		s.RequestKey == other.RequestKey &&
		reflect.DeepEqual(s.Target, other.Target) &&
		s.TTL == other.TTL
}

// SharedProviderRequest is the canonical discovery request produced by KRT for
// a shared fetch key. It is the unit the runtime fetcher watches.
type SharedProviderRequest struct {
	RequestKey remotehttp.FetchKey
	Issuer     string
	Target     remotehttp.FetchTarget
	// +noKrtEquals
	TLSConfig *tls.Config
	TTL       time.Duration
}

func (r SharedProviderRequest) ResourceName() string {
	return string(r.RequestKey)
}

func (r SharedProviderRequest) Equals(other SharedProviderRequest) bool {
	return r.RequestKey == other.RequestKey &&
		r.Issuer == other.Issuer &&
		reflect.DeepEqual(r.Target, other.Target) &&
		r.TTL == other.TTL
}

// ProviderSource returns the canonical runtime request consumed by the fetcher.
func (r SharedProviderRequest) ProviderSource() ProviderSource {
	return ProviderSource{
		Issuer:     r.Issuer,
		RequestKey: r.RequestKey,
		Target:     r.Target,
		TLSConfig:  r.TLSConfig,
		TTL:        r.TTL,
	}
}
