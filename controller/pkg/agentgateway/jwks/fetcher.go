package jwks

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

	"github.com/go-jose/go-jose/v4"
	"istio.io/istio/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// fetcher fetches and periodically refreshes remote JWKS keysets.
// Fetched keysets are stored in jwksCache and updates are sent to subscribers.
type fetcher struct {
	mu                sync.Mutex
	cache             *jwksCache
	defaultJwksClient JwksHttpClient
	requests          map[remotehttp.FetchKey]fetchState
	schedule          fetchingSchedule
	scheduled         map[remotehttp.FetchKey]*fetchAt
	subscribers       []chan sets.Set[remotehttp.FetchKey]
	wake              chan struct{}
}

type fetchState struct {
	source     JwksSource
	generation uint64
}

type fetchingSchedule []*fetchAt

const (
	initialRetryDelay = 100 * time.Millisecond
	maxRetryDelay     = 15 * time.Second
	maxRetryShift     = 30
	clientTimeout     = 10 * time.Second
)

//go:generate mockgen -destination mocks/mock_jwks_http_client.go -package mocks -source ./jwks_fetcher.go
type JwksHttpClient interface {
	FetchJwks(ctx context.Context, target remotehttp.FetchTarget) (jose.JSONWebKeySet, error)
}

type fetchAt struct {
	at           time.Time
	requestKey   remotehttp.FetchKey
	generation   uint64
	retryAttempt int
	index        int
}

type jwksHttpClientImpl struct {
	Client *http.Client
}

func newFetcher(cache *jwksCache) *fetcher {
	fetcher := &fetcher{
		cache:             cache,
		defaultJwksClient: &jwksHttpClientImpl{Client: makeClient(nil)},
		requests:          make(map[remotehttp.FetchKey]fetchState),
		schedule:          make([]*fetchAt, 0),
		scheduled:         make(map[remotehttp.FetchKey]*fetchAt),
		subscribers:       make([]chan sets.Set[remotehttp.FetchKey], 0),
		wake:              make(chan struct{}, 1),
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

// heap implementation
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
		f.maybeFetchJwks(ctx)

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
			// Drain the timer if it fired concurrently with wake so the next loop
			// iteration can safely reset it after a request was added, updated, or removed.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
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
		state, ok := f.lookup(fetch.requestKey)
		if !ok || state.generation != fetch.generation {
			continue
		}

		logger.Debug("fetching remote jwks", "request_key", fetch.requestKey, "jwks_uri", state.source.Target.URL)

		jwks, err := f.fetchJwks(ctx, state.source)
		if err != nil {
			next := nextRetryDelay(fetch.retryAttempt)
			logger.Error("error fetching jwks", "request_key", fetch.requestKey, "jwks_uri", state.source.Target.URL, "error", err, "retryAttempt", fetch.retryAttempt, "next", next.String())
			f.scheduleAt(fetch.requestKey, state.generation, now.Add(next), fetch.retryAttempt+1)
			continue
		}

		state, ok = f.lookup(fetch.requestKey)
		if !ok || state.generation != fetch.generation {
			continue
		}

		if err := f.cache.addJwks(fetch.requestKey, state.source.Target.URL, jwks); err != nil {
			logger.Error("error adding jwks", "request_key", fetch.requestKey, "jwks_uri", state.source.Target.URL, "error", err)
			next := nextRetryDelay(fetch.retryAttempt)
			f.scheduleAt(fetch.requestKey, state.generation, now.Add(next), fetch.retryAttempt+1)
			continue
		}

		f.scheduleAt(fetch.requestKey, state.generation, now.Add(state.source.TTL), 0)
		updates.Insert(fetch.requestKey)
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
		if scheduled := f.scheduled[requestKey]; scheduled != nil {
			heap.Remove(&f.schedule, scheduled.index)
			delete(f.scheduled, requestKey)
		}
	}
	f.mu.Unlock()

	if !ok {
		return
	}

	f.cache.deleteJwks(requestKey)
	f.notifySubscribers(sets.New(requestKey))

	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *fetcher) fetchJwks(ctx context.Context, source JwksSource) (jose.JSONWebKeySet, error) {
	if source.TLSConfig != nil {
		return (&jwksHttpClientImpl{Client: makeClient(source.TLSConfig)}).FetchJwks(ctx, source.Target)
	}
	return f.defaultJwksClient.FetchJwks(ctx, source.Target)
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

	var due []fetchAt
	for {
		maybeFetch := f.schedule.Peek()
		if maybeFetch == nil || maybeFetch.at.After(now) {
			return due
		}
		fetch := heap.Pop(&f.schedule).(*fetchAt)
		// The heap entry is no longer live once popped. Clear the index so a
		// later reschedule creates or fixes the current heap node instead of
		// trying to reuse a stale pointer that is no longer in the heap.
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
