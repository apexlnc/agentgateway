package oidc

import (
	"container/heap"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"istio.io/istio/pkg/slices"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

var fetchLogger = logging.New("oidc_fetcher")

type FetchingSchedule []fetchAt

type fetchAt struct {
	at           time.Time
	source       *ProviderSource
	retryAttempt int
}

type ProviderFetcher struct {
	mu            sync.Mutex
	cache         *providerCache
	defaultClient *http.Client
	sources       map[remotehttp.FetchKey]*ProviderSource
	schedule      FetchingSchedule
	subscribers   []chan map[remotehttp.FetchKey]struct{}
}

func NewProviderFetcher(cache *providerCache) *ProviderFetcher {
	f := &ProviderFetcher{
		cache:         cache,
		defaultClient: makeClient(nil),
		sources:       make(map[remotehttp.FetchKey]*ProviderSource),
		schedule:      make([]fetchAt, 0),
		subscribers:   make([]chan map[remotehttp.FetchKey]struct{}, 0),
	}
	heap.Init(&f.schedule)
	return f
}

func makeClient(t *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: t,
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
}

func (s FetchingSchedule) Len() int           { return len(s) }
func (s FetchingSchedule) Less(i, j int) bool { return s[i].at.Before(s[j].at) }
func (s FetchingSchedule) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s *FetchingSchedule) Push(x any)        { *s = append(*s, x.(fetchAt)) }
func (s *FetchingSchedule) Pop() any {
	old := *s
	n := len(old)
	item := old[n-1]
	*s = old[:n-1]
	return item
}
func (s FetchingSchedule) Peek() *fetchAt {
	if len(s) == 0 {
		return nil
	}
	return &s[0]
}

func (f *ProviderFetcher) SubscribeToUpdates() chan map[remotehttp.FetchKey]struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan map[remotehttp.FetchKey]struct{}, 8)
	f.subscribers = append(f.subscribers, ch)
	return ch
}

func (f *ProviderFetcher) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.maybeFetchProviders(ctx)
		}
	}
}

func (f *ProviderFetcher) AddOrUpdateSource(source ProviderSource) error {
	if _, err := url.Parse(source.Target.URL); err != nil {
		return fmt.Errorf("error parsing discovery url: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if existing, ok := f.sources[source.RequestKey]; ok {
		existing.Deleted = true
		delete(f.sources, source.RequestKey)
	}
	added := source
	f.sources[source.RequestKey] = &added
	heap.Push(&f.schedule, fetchAt{at: time.Now(), source: &added})
	return nil
}

func (f *ProviderFetcher) RemoveSource(source ProviderSource) {
	f.mu.Lock()
	if existing, ok := f.sources[source.RequestKey]; ok {
		existing.Deleted = true
		delete(f.sources, source.RequestKey)
		f.mu.Unlock()

		f.cache.Delete(source.RequestKey)
		f.notifySubscribers(map[remotehttp.FetchKey]struct{}{source.RequestKey: {}})
		return
	}
	f.mu.Unlock()
}

func (f *ProviderFetcher) maybeFetchProviders(ctx context.Context) {
	now := time.Now()
	pending := f.popDueFetches(now)
	if len(pending) == 0 {
		return
	}

	updates := make(map[remotehttp.FetchKey]struct{})
	for _, fetch := range pending {
		if fetch.source.Deleted {
			continue
		}

		cfg, err := fetchProviderConfig(ctx, f.defaultClient, *fetch.source)
		if err != nil {
			delay := min(100*time.Millisecond*time.Duration(math.Pow(2, float64(fetch.retryAttempt+1))), 15*time.Second)
			fetchLogger.Error("error fetching oidc provider", "request_key", fetch.source.RequestKey, "error", err, "retryAttempt", fetch.retryAttempt, "next", delay.String())
			f.reschedule(fetch, now.Add(delay), fetch.retryAttempt+1)
			continue
		}

		if !f.applyFetchedConfig(fetch, cfg, now.Add(fetch.source.TTL)) {
			continue
		}
		updates[fetch.source.RequestKey] = struct{}{}
	}

	if len(updates) > 0 {
		f.notifySubscribers(updates)
	}
}

func (f *ProviderFetcher) popDueFetches(now time.Time) []fetchAt {
	f.mu.Lock()
	defer f.mu.Unlock()

	var pending []fetchAt
	for {
		next := f.schedule.Peek()
		if next == nil || next.at.After(now) {
			return pending
		}
		pending = append(pending, heap.Pop(&f.schedule).(fetchAt))
	}
}

func (f *ProviderFetcher) reschedule(fetch fetchAt, at time.Time, retryAttempt int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	current, ok := f.sources[fetch.source.RequestKey]
	if !ok || current != fetch.source || fetch.source.Deleted {
		return
	}
	heap.Push(&f.schedule, fetchAt{
		at:           at,
		source:       fetch.source,
		retryAttempt: retryAttempt,
	})
}

func (f *ProviderFetcher) applyFetchedConfig(fetch fetchAt, cfg ProviderConfig, next time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	current, ok := f.sources[fetch.source.RequestKey]
	if !ok || current != fetch.source || fetch.source.Deleted {
		return false
	}

	f.cache.Set(fetch.source.RequestKey, cfg)
	heap.Push(&f.schedule, fetchAt{
		at:     next,
		source: fetch.source,
	})
	return true
}

func (f *ProviderFetcher) notifySubscribers(updates map[remotehttp.FetchKey]struct{}) {
	f.mu.Lock()
	subscribers := append([]chan map[remotehttp.FetchKey]struct{}(nil), f.subscribers...)
	f.mu.Unlock()

	for _, subscriber := range subscribers {
		subscriber <- updates
	}
}

type oidcDiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

func fetchProviderConfig(
	ctx context.Context,
	defaultClient *http.Client,
	source ProviderSource,
) (ProviderConfig, error) {
	discoveryURL, err := url.Parse(source.Target.URL)
	if err != nil {
		return ProviderConfig{}, fmt.Errorf("invalid discovery url: %w", err)
	}

	discoveryClient := defaultClient
	if source.TLSConfig != nil {
		discoveryClient = makeClient(source.TLSConfig)
	}

	documentBody, err := fetchBody(ctx, discoveryClient, discoveryURL.String())
	if err != nil {
		return ProviderConfig{}, fmt.Errorf("fetch discovery document: %w", err)
	}

	var document oidcDiscoveryDocument
	if err := json.Unmarshal(documentBody, &document); err != nil {
		return ProviderConfig{}, fmt.Errorf("decode discovery document: %w", err)
	}
	if document.Issuer != source.Issuer {
		return ProviderConfig{}, fmt.Errorf("oidc discovery issuer mismatch: expected %s, got %s", source.Issuer, document.Issuer)
	}

	authorizationEndpoint, err := parseHTTPURL(document.AuthorizationEndpoint)
	if err != nil {
		return ProviderConfig{}, fmt.Errorf("invalid authorization endpoint: %w", err)
	}
	tokenEndpoint, err := parseHTTPURL(document.TokenEndpoint)
	if err != nil {
		return ProviderConfig{}, fmt.Errorf("invalid token endpoint: %w", err)
	}
	jwksURL, err := parseHTTPURL(document.JwksURI)
	if err != nil {
		return ProviderConfig{}, fmt.Errorf("invalid jwks uri: %w", err)
	}

	tokenEndpointAuth, err := parseTokenEndpointAuthMethods(document.TokenEndpointAuthMethodsSupported)
	if err != nil {
		return ProviderConfig{}, err
	}

	jwksClient := defaultClient
	if sameAuthority(discoveryURL, jwksURL) {
		jwksClient = discoveryClient
	} else if jwksURL.Scheme != "https" {
		return ProviderConfig{}, fmt.Errorf("cross-authority jwks uri must use https, got %s", jwksURL.String())
	}

	jwksBody, err := fetchBody(ctx, jwksClient, jwksURL.String())
	if err != nil {
		return ProviderConfig{}, fmt.Errorf("fetch jwks: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksBody, &jwks); err != nil {
		return ProviderConfig{}, fmt.Errorf("decode jwks: %w", err)
	}
	jwksInline, err := json.Marshal(jwks)
	if err != nil {
		return ProviderConfig{}, fmt.Errorf("serialize jwks: %w", err)
	}

	return ProviderConfig{
		RequestKey:            source.RequestKey,
		DiscoveryURL:          discoveryURL.String(),
		FetchedAt:             time.Now().UTC(),
		Issuer:                document.Issuer,
		AuthorizationEndpoint: authorizationEndpoint.String(),
		TokenEndpoint:         tokenEndpoint.String(),
		TokenEndpointAuth:     tokenEndpointAuth,
		JwksURI:               jwksURL.String(),
		JwksInline:            string(jwksInline),
	}, nil
}

func fetchBody(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, rawURL)
	}
	return io.ReadAll(resp.Body)
}

func sameAuthority(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && a.Host == b.Host
}

func parseHTTPURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("expected http or https scheme, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	return parsed, nil
}

func parseTokenEndpointAuthMethods(methods []string) (string, error) {
	if len(methods) == 0 {
		return "clientSecretBasic", nil
	}
	if slices.Contains(methods, "client_secret_basic") {
		return "clientSecretBasic", nil
	}
	if slices.Contains(methods, "client_secret_post") {
		return "clientSecretPost", nil
	}
	return "", fmt.Errorf("token endpoint auth methods must include clientSecretBasic or clientSecretPost")
}
