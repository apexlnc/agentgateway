package jwks

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

var fetcherLogger = logging.New("jwks_fetcher")

// Fetcher fetches and periodically refreshes remote JWKS keysets.
// Fetched keysets are published as KRT-visible Results.
type Fetcher = remotecache.Fetcher[SharedJwksRequest, Keyset]

func NewFetcher(results *JwksResults) *Fetcher {
	driver := &JwksDriver{DefaultClient: remotehttp.NewDefaultFetchClient()}
	return remotecache.NewFetcher[SharedJwksRequest, Keyset](results, driver, fetcherLogger)
}

type JwksDriver struct {
	DefaultClient *http.Client
}

func (d *JwksDriver) Fetch(ctx context.Context, source SharedJwksRequest) (Keyset, error) {
	client, err := remotehttp.PickClient(d.DefaultClient, source.Target, source.TLSConfig, source.ProxyTLSConfig)
	if err != nil {
		return Keyset{}, err
	}

	fetcherLogger.InfoContext(ctx, "fetching jwks", "url", source.Target.URL)

	jwks, err := remotehttp.FetchJSON[jose.JSONWebKeySet](ctx, client, source.Target, "JWKS")
	if err != nil {
		return Keyset{}, err
	}
	// Reject empty keysets at fetch time. An IdP returning a non-JWKS body
	// (e.g. an error envelope as 200 OK) decodes into an empty Keys slice;
	// persisting it would silently fail JWT validation in the dataplane.
	if len(jwks.Keys) == 0 {
		return Keyset{}, fmt.Errorf("JWKS response from %s contains no keys", source.Target.URL)
	}

	return buildKeyset(source.RequestKey, source.Target.URL, jwks)
}
