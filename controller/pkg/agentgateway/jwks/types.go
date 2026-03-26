package jwks

import (
	"crypto/tls"
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
	TLSConfig  *tls.Config
	TTL        time.Duration
	Deleted    bool
}

func (s JwksSource) ResourceName() string {
	return s.OwnerKey.String()
}
