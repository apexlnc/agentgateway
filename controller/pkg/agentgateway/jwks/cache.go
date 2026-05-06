package jwks

import (
	"encoding/json"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// JwksResults stores fetched JWKS keysets as a KRT-visible collection.
type JwksResults = remotecache.Results[Keyset]

// NewResults constructs an empty JWKS result collection.
func NewResults() *JwksResults {
	return remotecache.NewResults[Keyset]()
}

func buildKeyset(requestKey remotehttp.FetchKey, requestURL string, jwks jose.JSONWebKeySet) (Keyset, error) {
	serializedJwks, err := json.Marshal(jwks)
	if err != nil {
		return Keyset{}, err
	}
	return Keyset{
		RequestKey: requestKey,
		URL:        requestURL,
		FetchedAt:  time.Now(),
		JwksJSON:   string(serializedJwks),
	}, nil
}
