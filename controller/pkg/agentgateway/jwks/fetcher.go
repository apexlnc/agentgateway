package jwks

import (
	"context"
	"net/http"

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
	_, jwks, err := remotehttp.FetchJWKSBody(ctx, client, source.Target.URL, "JWKS")
	if err != nil {
		return Keyset{}, err
	}
	return buildKeyset(source.RequestKey, source.Target.URL, jwks)
}
