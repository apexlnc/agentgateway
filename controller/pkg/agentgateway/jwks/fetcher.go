package jwks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"istio.io/istio/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/internal/remotefetch"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// fetcher fetches and periodically refreshes remote JWKS keysets.
// Fetched keysets are stored in jwksCache and updates are sent to subscribers.
type fetcher struct {
	mu                sync.Mutex
	cache             *jwksCache
	providers         oidc.ProviderReader
	defaultJwksClient JwksHttpClient
	requests          map[remotehttp.FetchKey]fetchState
	schedule          *remotefetch.Schedule
	subscribers       []chan sets.Set[remotehttp.FetchKey]
	wake              chan struct{}
}

type fetchState struct {
	source     JwksSource
	generation uint64
}

const (
	maxRetryDelay = remotefetch.MaxRetryDelay
)

type JwksHttpClient interface {
	FetchJwks(ctx context.Context, target remotehttp.FetchTarget) (jose.JSONWebKeySet, error)
}

type fetchAt = remotefetch.Entry

type jwksHttpClientImpl struct {
	Client *http.Client
}

func newFetcher(cache *jwksCache) *fetcher {
	return newFetcherWithProviders(cache, nil)
}

func newFetcherWithProviders(cache *jwksCache, providers oidc.ProviderReader) *fetcher {
	fetcher := &fetcher{
		cache:             cache,
		providers:         providers,
		defaultJwksClient: &jwksHttpClientImpl{Client: remotefetch.MakeClient(nil)},
		requests:          make(map[remotehttp.FetchKey]fetchState),
		schedule:          remotefetch.NewSchedule(),
		subscribers:       make([]chan sets.Set[remotehttp.FetchKey], 0),
		wake:              make(chan struct{}, 1),
	}

	return fetcher
}

func nextRetryDelay(retryAttempt int) time.Duration {
	return remotefetch.NextRetryDelay(retryAttempt)
}

func (f *fetcher) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		f.maybeFetchJwks(ctx)

		f.mu.Lock()
		next := f.schedule.Peek()
		var delay time.Duration
		if next == nil {
			delay = time.Hour
		} else {
			delay = time.Until(next.At)
		}
		f.mu.Unlock()

		if delay < 0 {
			delay = 0
		}
		timer.Reset(delay)

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-f.wake:
			// Drain the timer if it fired concurrently with wake so the next loop
			// iteration can safely reset it after a request was added, updated, or removed.
			remotefetch.DrainTimer(timer)
		}
	}
}

func (f *fetcher) maybeFetchJwks(ctx context.Context) {
	now := time.Now()
	due := f.popDue(now)
	if len(due) == 0 {
		return
	}

	updates := sets.New[remotehttp.FetchKey]()
	for _, fetch := range due {
		state, ok := f.lookup(fetch.RequestKey)
		if !ok || state.generation != fetch.Generation {
			continue
		}

		logger.Debug("fetching jwks", "request_key", fetch.RequestKey, "target", state.source.Target.URL, "discovery", state.source.Discovery)

		requestURL, jwks, err := f.fetchJwks(ctx, state.source)
		if err != nil {
			next := nextRetryDelay(fetch.RetryAttempt)
			logger.Error("error fetching jwks", "request_key", fetch.RequestKey, "target", state.source.Target.URL, "error", err, "retryAttempt", fetch.RetryAttempt, "next", next.String())
			f.scheduleAt(fetch.RequestKey, state.generation, now.Add(next), fetch.RetryAttempt+1)
			continue
		}

		state, ok = f.lookup(fetch.RequestKey)
		if !ok || state.generation != fetch.Generation {
			continue
		}

		if err := f.cache.addJwks(fetch.RequestKey, requestURL, jwks); err != nil {
			logger.Error("error adding jwks", "request_key", fetch.RequestKey, "jwks_uri", requestURL, "error", err)
			next := nextRetryDelay(fetch.RetryAttempt)
			f.scheduleAt(fetch.RequestKey, state.generation, now.Add(next), fetch.RetryAttempt+1)
			continue
		}

		f.scheduleAt(fetch.RequestKey, state.generation, now.Add(state.source.TTL), 0)
		updates.Insert(fetch.RequestKey)
	}

	if !updates.IsEmpty() {
		f.notifySubscribers(updates)
	}
}

func (f *fetcher) SubscribeToUpdates() <-chan sets.Set[remotehttp.FetchKey] {
	f.mu.Lock()
	defer f.mu.Unlock()

	subscriber := make(chan sets.Set[remotehttp.FetchKey], 1)
	f.subscribers = append(f.subscribers, subscriber)

	return subscriber
}

func (f *fetcher) AddOrUpdateKeyset(source JwksSource) error {
	if _, err := url.Parse(source.Target.URL); err != nil {
		return fmt.Errorf("error parsing jwks url %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	state := f.requests[source.RequestKey]
	state.generation++
	state.source = source
	f.requests[source.RequestKey] = state
	f.scheduleAtLocked(source.RequestKey, state.generation, time.Now(), 0)

	return nil
}

func (f *fetcher) RemoveKeyset(requestKey remotehttp.FetchKey) {
	f.mu.Lock()
	_, ok := f.requests[requestKey]
	if ok {
		delete(f.requests, requestKey)
		f.schedule.Remove(requestKey)
	}
	f.mu.Unlock()

	if !ok {
		return
	}

	f.cache.deleteJwks(requestKey)
	f.notifySubscribers(sets.New(requestKey))
	remotefetch.Signal(f.wake)
}

func (f *fetcher) fetchJwks(ctx context.Context, source JwksSource) (string, jose.JSONWebKeySet, error) {
	target := source.Target
	tlsConfig := source.TLSConfig
	if source.Discovery {
		if f.providers == nil {
			return "", jose.JSONWebKeySet{}, fmt.Errorf("oidc lookup is not configured for request %q (%s)", source.RequestKey, source.Target.URL)
		}
		provider, ok := f.providers.ProviderByRequestKey(source.RequestKey)
		if !ok {
			return "", jose.JSONWebKeySet{}, fmt.Errorf("oidc provider config for %q isn't available (not yet fetched or fetch failed)", source.Target.URL)
		}
		if err := oidc.ValidateProviderForIssuer(source.Issuer, provider); err != nil {
			return "", jose.JSONWebKeySet{}, err
		}
		var err error
		target, err = oidc.DiscoveredJWKSTarget(source.Issuer, provider)
		if err != nil {
			return "", jose.JSONWebKeySet{}, err
		}
		shareAuthority, err := oidc.URLsShareAuthority(source.Target.URL, target.URL)
		if err != nil {
			return "", jose.JSONWebKeySet{}, err
		}
		if !shareAuthority {
			tlsConfig = nil
		}
	}

	jwks, err := f.fetchJwksFromTarget(ctx, tlsConfig, target)
	if err != nil {
		return "", jose.JSONWebKeySet{}, err
	}
	return target.URL, jwks, nil
}

func (f *fetcher) fetchJwksFromTarget(ctx context.Context, tlsConfig *tls.Config, target remotehttp.FetchTarget) (jose.JSONWebKeySet, error) {
	if tlsConfig != nil {
		return (&jwksHttpClientImpl{Client: remotefetch.MakeClient(tlsConfig)}).FetchJwks(ctx, target)
	}
	return f.defaultJwksClient.FetchJwks(ctx, target)
}

func (c *jwksHttpClientImpl) FetchJwks(ctx context.Context, target remotehttp.FetchTarget) (jose.JSONWebKeySet, error) {
	log := log.FromContext(ctx)
	log.Info("fetching jwks", "url", target.URL)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("could not build request to get JWKS: %w", err)
	}

	response, err := c.Client.Do(request)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, fmt.Errorf("unexpected status code from jwks endpoint at %s: %d", target.URL, response.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&jwks); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("could not decode jwks: %w", err)
	}

	return jwks, nil
}

func (f *fetcher) popDue(now time.Time) []fetchAt {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.schedule.PopDue(now)
}

func (f *fetcher) lookup(requestKey remotehttp.FetchKey) (fetchState, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	state, ok := f.requests[requestKey]
	return state, ok
}

func (f *fetcher) scheduleAt(requestKey remotehttp.FetchKey, generation uint64, at time.Time, retryAttempt int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.scheduleAtLocked(requestKey, generation, at, retryAttempt)
}

func (f *fetcher) scheduleAtLocked(requestKey remotehttp.FetchKey, generation uint64, at time.Time, retryAttempt int) {
	if _, ok := f.requests[requestKey]; !ok {
		return
	}

	f.schedule.Schedule(requestKey, generation, at, retryAttempt)
	remotefetch.Signal(f.wake)
}

func (f *fetcher) notifySubscribers(updates sets.Set[remotehttp.FetchKey]) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, subscriber := range f.subscribers {
		merged := cloneRequestKeySet(updates)
		select {
		case existing := <-subscriber:
			merged.Merge(existing)
		default:
		}
		subscriber <- merged
	}
}

func cloneRequestKeySet(updates sets.Set[remotehttp.FetchKey]) sets.Set[remotehttp.FetchKey] {
	if updates == nil {
		return sets.New[remotehttp.FetchKey]()
	}
	return updates.Copy()
}
