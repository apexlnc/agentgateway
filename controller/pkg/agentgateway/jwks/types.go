package jwks

import (
	"crypto/tls"
	"reflect"
	"time"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type Keyset struct {
	RequestKey remotehttp.FetchKey `json:"requestKey"`
	URL        string              `json:"url"`
	FetchedAt  time.Time           `json:"fetchedAt"`
	JwksJSON   string              `json:"jwks"`
}

type JwksSource struct {
	OwnerKey   OwnerKey
	RequestKey remotehttp.FetchKey
	Target     remotehttp.FetchTarget
	// +noKrtEquals
	TLSConfig *tls.Config
	TTL       time.Duration
	Issuer    string
	Discovery bool
}

func (s JwksSource) ResourceName() string {
	return s.OwnerKey.String()
}

func (s JwksSource) Equals(other JwksSource) bool {
	return s.OwnerKey == other.OwnerKey &&
		s.RequestKey == other.RequestKey &&
		reflect.DeepEqual(s.Target, other.Target) &&
		s.TTL == other.TTL &&
		s.Issuer == other.Issuer &&
		s.Discovery == other.Discovery
}

type SharedJwksRequest struct {
	RequestKey remotehttp.FetchKey
	Target     remotehttp.FetchTarget
	// +noKrtEquals
	TLSConfig *tls.Config
	TTL       time.Duration
	Issuer    string
	Discovery bool
}

func (r SharedJwksRequest) ResourceName() string {
	return string(r.RequestKey)
}

func (r SharedJwksRequest) Equals(other SharedJwksRequest) bool {
	return r.RequestKey == other.RequestKey &&
		reflect.DeepEqual(r.Target, other.Target) &&
		r.TTL == other.TTL &&
		r.Issuer == other.Issuer &&
		r.Discovery == other.Discovery
}

func (r SharedJwksRequest) JwksSource() JwksSource {
	return JwksSource{
		RequestKey: r.RequestKey,
		Target:     r.Target,
		TLSConfig:  r.TLSConfig,
		TTL:        r.TTL,
		Issuer:     r.Issuer,
		Discovery:  r.Discovery,
	}
}
