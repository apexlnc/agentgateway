package oidc

import (
	"container/heap"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type fetcher struct {
	mu                    sync.Mutex
	cache                 *providerCache
	defaultProviderClient ProviderHTTPClient
	requests              map[remotehttp.FetchKey]fetchState
	schedule              fetchingSchedule
	scheduled             map[remotehttp.FetchKey]*fetchAt
	wake                  chan struct{}
}

type fetchState struct {
	source     ProviderSource
	generation uint64
}

type fetchingSchedule []*fetchAt

const (
	initialRetryDelay = 100 * time.Millisecond
	maxRetryDelay     = 15 * time.Second
	maxRetryShift     = 30
	clientTimeout     = 10 * time.Second
)

type ProviderHTTPClient interface {
	FetchProviderConfig(ctx context.Context, target remotehttp.FetchTarget) (ProviderConfig, error)
}

type fetchAt struct {
	at           time.Time
	requestKey   remotehttp.FetchKey
	generation   uint64
	retryAttempt int
	index        int
}

type providerHTTPClientImpl struct {
	Client *http.Client
}

type providerMetadataResponse struct {
	Issuer                string `json:"issuer"`
	JwksURI               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func newFetcher(cache *providerCache) *fetcher {
	fetcher := &fetcher{
		cache:                 cache,
		defaultProviderClient: &providerHTTPClientImpl{Client: makeClient(nil)},
		requests:              make(map[remotehttp.FetchKey]fetchState),
		schedule:              make([]*fetchAt, 0),
		scheduled:             make(map[remotehttp.FetchKey]*fetchAt),
		wake:                  make(chan struct{}, 1),
	}
	heap.Init(&fetcher.schedule)
	return fetcher
}

func makeClient(t *tls.Config) *http.Client {
	return &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: t,
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			DisableKeepAlives: true,
		},
	}
}

func (s fetchingSchedule) Len() int           { return len(s) }
func (s fetchingSchedule) Less(i, j int) bool { return s[i].at.Before(s[j].at) }
func (s fetchingSchedule) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
	s[i].index = i
	s[j].index = j
}
func (s *fetchingSchedule) Push(x any) {
	entry := x.(*fetchAt)
	entry.index = len(*s)
	*s = append(*s, entry)
}
func (s *fetchingSchedule) Pop() any {
	old := *s
	n := len(old)
	x := old[n-1]
	x.index = -1
	old[n-1] = nil
	*s = old[0 : n-1]
	return x
}
func (s fetchingSchedule) Peek() *fetchAt {
	if len(s) == 0 {
		return nil
	}
	return s[0]
}

func nextRetryDelay(retryAttempt int) time.Duration {
	shift := min(retryAttempt+1, maxRetryShift)

	next := initialRetryDelay * time.Duration(1<<shift)
	if next > maxRetryDelay {
		return maxRetryDelay
	}

	return next
}

func (f *fetcher) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		f.maybeFetchProviderConfig(ctx)

		f.mu.Lock()
		next := f.schedule.Peek()
		var delay time.Duration
		if next == nil {
			delay = time.Hour
		} else {
			delay = time.Until(next.at)
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
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}
}

func (f *fetcher) maybeFetchProviderConfig(ctx context.Context) {
	now := time.Now()
	due := f.popDue(now)
	if len(due) == 0 {
		return
	}

	for _, fetch := range due {
		state, ok := f.lookup(fetch.requestKey)
		if !ok || state.generation != fetch.generation {
			continue
		}

		logger.Debug("fetching oidc provider metadata", "request_key", fetch.requestKey, "discovery_url", state.source.Target.URL)

		provider, err := f.fetchProviderConfig(ctx, state.source)
		if err != nil {
			next := nextRetryDelay(fetch.retryAttempt)
			logger.Error("error fetching oidc provider metadata", "request_key", fetch.requestKey, "discovery_url", state.source.Target.URL, "error", err, "retryAttempt", fetch.retryAttempt, "next", next.String())
			f.scheduleAt(fetch.requestKey, state.generation, now.Add(next), fetch.retryAttempt+1)
			continue
		}

		state, ok = f.lookup(fetch.requestKey)
		if !ok || state.generation != fetch.generation {
			continue
		}

		if err := f.cache.addProvider(fetch.requestKey, state.source.Target.URL, provider); err != nil {
			logger.Error("error adding oidc provider metadata", "request_key", fetch.requestKey, "discovery_url", state.source.Target.URL, "error", err)
			next := nextRetryDelay(fetch.retryAttempt)
			f.scheduleAt(fetch.requestKey, state.generation, now.Add(next), fetch.retryAttempt+1)
			continue
		}

		f.scheduleAt(fetch.requestKey, state.generation, now.Add(state.source.TTL), 0)
	}
}

func (f *fetcher) AddOrUpdateProvider(source ProviderSource) error {
	if _, err := url.Parse(source.Target.URL); err != nil {
		return fmt.Errorf("error parsing discovery url %w", err)
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

func (f *fetcher) RemoveProvider(requestKey remotehttp.FetchKey) {
	f.mu.Lock()
	_, ok := f.requests[requestKey]
	if ok {
		delete(f.requests, requestKey)
		if scheduled := f.scheduled[requestKey]; scheduled != nil {
			heap.Remove(&f.schedule, scheduled.index)
			delete(f.scheduled, requestKey)
		}
	}
	f.mu.Unlock()

	if !ok {
		return
	}

	f.cache.deleteProvider(requestKey)

	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *fetcher) fetchProviderConfig(ctx context.Context, source ProviderSource) (ProviderConfig, error) {
	var (
		provider ProviderConfig
		err      error
	)
	if source.TLSConfig != nil {
		provider, err = (&providerHTTPClientImpl{Client: makeClient(source.TLSConfig)}).FetchProviderConfig(ctx, source.Target)
	} else {
		provider, err = f.defaultProviderClient.FetchProviderConfig(ctx, source.Target)
	}
	if err != nil {
		return ProviderConfig{}, err
	}
	if err := ValidateProviderForIssuer(source.Issuer, provider); err != nil {
		return ProviderConfig{}, err
	}
	return provider, nil
}

func (c *providerHTTPClientImpl) FetchProviderConfig(ctx context.Context, target remotehttp.FetchTarget) (ProviderConfig, error) {
	log := log.FromContext(ctx)
	log.Info("fetching oidc provider metadata", "url", target.URL)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return ProviderConfig{}, fmt.Errorf("could not build request to get oidc metadata: %w", err)
	}

	response, err := c.Client.Do(request)
	if err != nil {
		return ProviderConfig{}, err
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode != http.StatusOK {
		return ProviderConfig{}, fmt.Errorf("unexpected status code from oidc discovery endpoint at %s: %d", target.URL, response.StatusCode)
	}

	var metadata providerMetadataResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&metadata); err != nil {
		return ProviderConfig{}, fmt.Errorf("could not decode oidc provider metadata: %w", err)
	}

	provider := ProviderConfig{
		FetchedAt:             time.Now().UTC(),
		Issuer:                metadata.Issuer,
		JwksURI:               metadata.JwksURI,
		AuthorizationEndpoint: metadata.AuthorizationEndpoint,
		TokenEndpoint:         metadata.TokenEndpoint,
		EndSessionEndpoint:    metadata.EndSessionEndpoint,
	}
	if err := ValidateProviderConfig(provider); err != nil {
		return ProviderConfig{}, err
	}

	return provider, nil
}

func (f *fetcher) popDue(now time.Time) []fetchAt {
	f.mu.Lock()
	defer f.mu.Unlock()

	var due []fetchAt
	for {
		maybeFetch := f.schedule.Peek()
		if maybeFetch == nil || maybeFetch.at.After(now) {
			return due
		}
		fetch := heap.Pop(&f.schedule).(*fetchAt)
		delete(f.scheduled, fetch.requestKey)
		due = append(due, *fetch)
	}
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

	if scheduled := f.scheduled[requestKey]; scheduled != nil {
		scheduled.at = at
		scheduled.generation = generation
		scheduled.retryAttempt = retryAttempt
		heap.Fix(&f.schedule, scheduled.index)
	} else {
		entry := &fetchAt{
			at:           at,
			requestKey:   requestKey,
			generation:   generation,
			retryAttempt: retryAttempt,
			index:        -1,
		}
		heap.Push(&f.schedule, entry)
		f.scheduled[requestKey] = entry
	}

	select {
	case f.wake <- struct{}{}:
	default:
	}
}
