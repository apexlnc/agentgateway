// Package oidc derives controller-side OIDC discovery requests from
// AgentgatewayPolicy and adapts resolved provider metadata into xDS.
package oidc

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"time"

	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/slices"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

const (
	oidcRequestKeyDomain = "oidc-discovery"
)

// DiscoveredProvider holds the metadata from a successful OIDC discovery fetch,
// including the JWKS key material fetched from the discovery document's jwks_uri.
type DiscoveredProvider struct {
	RequestKey remotehttp.FetchKey `json:"requestKey"`
	// IssuerURL is the IdP-reported issuer, validated byte-exact against the user-configured issuer.
	IssuerURL                         string    `json:"issuerURL"`
	AuthorizationEndpoint             string    `json:"authorizationEndpoint"`
	TokenEndpoint                     string    `json:"tokenEndpoint"`
	JwksURI                           string    `json:"jwksURI"`
	JwksInline                        string    `json:"jwksInline"`
	TokenEndpointAuthMethodsSupported []string  `json:"tokenEndpointAuthMethodsSupported,omitempty"`
	FetchedAt                         time.Time `json:"fetchedAt"`
}

func (p DiscoveredProvider) RemoteRequestKey() remotehttp.FetchKey {
	return p.RequestKey
}

func (p DiscoveredProvider) RemoteFetchedAt() time.Time {
	return p.FetchedAt
}

func (p DiscoveredProvider) ResourceName() string { return string(p.RequestKey) }

// Equals compares JwksInline last so the multi-KB string compare short-circuits
// on cheaper-field diffs.
func (p DiscoveredProvider) Equals(other DiscoveredProvider) bool {
	return p.RequestKey == other.RequestKey &&
		p.IssuerURL == other.IssuerURL &&
		p.AuthorizationEndpoint == other.AuthorizationEndpoint &&
		p.TokenEndpoint == other.TokenEndpoint &&
		p.JwksURI == other.JwksURI &&
		slices.Equal(p.TokenEndpointAuthMethodsSupported, other.TokenEndpointAuthMethodsSupported) &&
		p.FetchedAt.Equal(other.FetchedAt) &&
		p.JwksInline == other.JwksInline
}

var (
	_ krt.ResourceNamer               = DiscoveredProvider{}
	_ krt.Equaler[DiscoveredProvider] = DiscoveredProvider{}
)

// OidcSource is a per-owner OIDC discovery request before KRT collapses
// equivalent sources onto a shared request key.
type OidcSource struct {
	OwnerKey       remotecache.OwnerID
	RequestKey     remotehttp.FetchKey
	ExpectedIssuer string
	Target         remotehttp.FetchTarget
	// ProviderBackendTarget is set when provider calls should go through a
	// resolved backend transport instead of connecting directly to provider URLs.
	ProviderBackendTarget *remotehttp.FetchTarget
	// +noKrtEquals
	TLSConfig *tls.Config
	// +noKrtEquals
	ProxyTLSConfig *tls.Config
	TTL            time.Duration
}

func (s OidcSource) ResourceName() string {
	return s.OwnerKey.String()
}

func (s OidcSource) RemoteRequestKey() remotehttp.FetchKey {
	return s.RequestKey
}

func (s OidcSource) RemoteTTL() time.Duration {
	return s.TTL
}

func (s OidcSource) Equals(other OidcSource) bool {
	return s.OwnerKey == other.OwnerKey &&
		s.RequestKey == other.RequestKey &&
		s.ExpectedIssuer == other.ExpectedIssuer &&
		s.Target.Equals(other.Target) &&
		fetchTargetPtrEqual(s.ProviderBackendTarget, other.ProviderBackendTarget) &&
		s.TTL == other.TTL
}

// SharedOidcRequest is the canonical OIDC discovery request KRT produces per
// shared fetch key; the unit the Fetcher and persistence layer watch.
type SharedOidcRequest struct {
	RequestKey     remotehttp.FetchKey
	ExpectedIssuer string
	Target         remotehttp.FetchTarget
	// ProviderBackendTarget is set when provider calls should go through a
	// resolved backend transport instead of connecting directly to provider URLs.
	ProviderBackendTarget *remotehttp.FetchTarget
	// +noKrtEquals
	TLSConfig *tls.Config
	// +noKrtEquals
	ProxyTLSConfig *tls.Config
	TTL            time.Duration
}

func (r SharedOidcRequest) ResourceName() string {
	return string(r.RequestKey)
}

func (r SharedOidcRequest) RemoteRequestKey() remotehttp.FetchKey {
	return r.RequestKey
}

func (r SharedOidcRequest) RemoteTTL() time.Duration {
	return r.TTL
}

func (r SharedOidcRequest) Equals(other SharedOidcRequest) bool {
	return r.RequestKey == other.RequestKey &&
		r.ExpectedIssuer == other.ExpectedIssuer &&
		r.Target.Equals(other.Target) &&
		fetchTargetPtrEqual(r.ProviderBackendTarget, other.ProviderBackendTarget) &&
		r.TTL == other.TTL
}

// fetchTargetPtrEqual compares two optional FetchTarget pointers without
// reflect, using FetchTarget.Equals for non-nil pairs.
func fetchTargetPtrEqual(a, b *remotehttp.FetchTarget) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Equals(*b)
	}
}

// oidcRequestKey domain-separates by (target, expectedIssuer,
// providerBackendTarget) — all three are part of trust identity.
func oidcRequestKey(target remotehttp.FetchTarget, expectedIssuer string, providerBackendTarget *remotehttp.FetchTarget) remotehttp.FetchKey {
	hash := sha256.New()
	writeHashPart := func(value string) {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}

	writeHashPart(oidcRequestKeyDomain)
	writeHashPart(target.Key().String())
	writeHashPart(expectedIssuer)
	if providerBackendTarget == nil {
		writeHashPart("direct")
	} else {
		writeHashPart("provider-backend")
		writeHashPart(providerBackendTarget.Key().String())
	}

	return remotehttp.FetchKey(hex.EncodeToString(hash.Sum(nil)))
}
