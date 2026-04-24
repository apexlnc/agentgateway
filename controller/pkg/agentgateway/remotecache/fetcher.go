package remotecache

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type Request interface {
	RemoteRequestKey() remotehttp.FetchKey
	RemoteTTL() time.Duration
}

type Result interface {
	RemoteRequestKey() remotehttp.FetchKey
	RemoteFetchedAt() time.Time
}

type Driver[S Request, R Result] interface {
	Fetch(ctx context.Context, source S) (R, error)
}

type InternalFetchState[S Request] struct {
	Source     S
	Generation uint64
}

// Fetcher owns the imperative side (timers, retries, HTTP) and publishes results into
// FetchedResults so downstream KRT graphs react via normal event propagation.
type Fetcher[S Request, R Result] struct {
	mu       sync.Mutex
	Results  *FetchedResults[R]
	Driver   Driver[S, R]
	requests map[remotehttp.FetchKey]InternalFetchState[S]
	schedule *Schedule
	wake     chan struct{}
	logger   *slog.Logger
}

func NewFetcher[S Request, R Result](results *FetchedResults[R], driver Driver[S, R], logger *slog.Logger) *Fetcher[S, R] {
	return &Fetcher[S, R]{
		Results:  results,
		Driver:   driver,
		requests: make(map[remotehttp.FetchKey]InternalFetchState[S]),
		schedule: NewSchedule(),
		wake:     make(chan struct{}, 1),
		logger:   logger,
	}
}

func (f *Fetcher[S, R]) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	DrainTimer(timer)
	defer timer.Stop()

	for {
		f.MaybeFetch(ctx)

		f.mu.Lock()
		next, ok := f.schedule.Peek()
		var delay time.Duration
		if !ok {
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
			DrainTimer(timer)
		}
	}
}

func (f *Fetcher[S, R]) MaybeFetch(ctx context.Context) {
	now := time.Now()
	due := f.popDue(now)
	if len(due) == 0 {
		return
	}

	for _, fetch := range due {
		state, ok := f.lookup(fetch.RequestKey)
		if !ok || state.Generation != fetch.Generation {
			continue
		}

		f.logger.Debug("fetching remote resource", "request_key", fetch.RequestKey)
		result, err := f.Driver.Fetch(ctx, state.Source)
		if err != nil {
			next := NextRetryDelay(fetch.RetryAttempt)
			f.logger.Error("error fetching remote resource", "request_key", fetch.RequestKey, "error", err, "retryAttempt", fetch.RetryAttempt, "next", next.String())
			f.scheduleAt(fetch.RequestKey, state.Generation, now.Add(next), fetch.RetryAttempt+1)
			continue
		}

		if !f.commitFetchResult(fetch.RequestKey, fetch.Generation, result, now.Add(state.Source.RemoteTTL())) {
			continue
		}
	}

	f.sweepRetiredResults()
}

func (f *Fetcher[S, R]) AddOrUpdate(source S) {
	requestKey := source.RemoteRequestKey()
	nextFetchAt := time.Now()
	if cached, ok := f.Results.Get(requestKey); ok {
		if fetchedAt := cached.RemoteFetchedAt(); !fetchedAt.IsZero() {
			expiresAt := fetchedAt.Add(source.RemoteTTL())
			if expiresAt.After(nextFetchAt) {
				nextFetchAt = expiresAt
			}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	state := f.requests[requestKey]
	state.Generation++
	state.Source = source
	f.requests[requestKey] = state
	f.scheduleAtLocked(requestKey, state.Generation, nextFetchAt, 0)
}

func (f *Fetcher[S, R]) Remove(requestKey remotehttp.FetchKey) {
	f.mu.Lock()
	_, hadRequest := f.requests[requestKey]
	if hadRequest {
		delete(f.requests, requestKey)
		f.schedule.Remove(requestKey)
	}
	f.mu.Unlock()

	hadResult := f.Results.Delete(requestKey)
	if hadRequest {
		SignalWake(f.wake)
	}
	if !hadRequest && !hadResult {
		return
	}
}

func (f *Fetcher[S, R]) Retire(requestKey remotehttp.FetchKey) {
	f.mu.Lock()
	_, hadRequest := f.requests[requestKey]
	if hadRequest {
		delete(f.requests, requestKey)
		f.schedule.Remove(requestKey)
	}
	f.mu.Unlock()

	if hadRequest {
		SignalWake(f.wake)
	}
}

func (f *Fetcher[S, R]) SweepOrphans() {
	f.sweepRetiredResults()
}

func (f *Fetcher[S, R]) popDue(now time.Time) []FetchAt {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.schedule.PopDue(now)
}

func (f *Fetcher[S, R]) lookup(requestKey remotehttp.FetchKey) (InternalFetchState[S], bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.requests[requestKey]
	return state, ok
}

func (f *Fetcher[S, R]) commitFetchResult(requestKey remotehttp.FetchKey, generation uint64, result R, nextFetchAt time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	state, ok := f.requests[requestKey]
	if !ok || state.Generation != generation {
		return false
	}

	f.Results.Put(result)
	f.scheduleAtLocked(requestKey, generation, nextFetchAt, 0)
	return true
}

func (f *Fetcher[S, R]) sweepRetiredResults() {
	f.mu.Lock()
	live := make(map[remotehttp.FetchKey]struct{}, len(f.requests))
	for key := range f.requests {
		live[key] = struct{}{}
	}
	f.mu.Unlock()

	f.Results.DeleteObjects(func(record FetchedRecord[R]) bool {
		_, ok := live[record.Payload.RemoteRequestKey()]
		return !ok
	})
}

func (f *Fetcher[S, R]) scheduleAt(requestKey remotehttp.FetchKey, generation uint64, at time.Time, retryAttempt int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scheduleAtLocked(requestKey, generation, at, retryAttempt)
}

func (f *Fetcher[S, R]) scheduleAtLocked(requestKey remotehttp.FetchKey, generation uint64, at time.Time, retryAttempt int) {
	if _, ok := f.requests[requestKey]; !ok {
		return
	}
	f.schedule.Schedule(requestKey, generation, at, retryAttempt)
	SignalWake(f.wake)
}

func (f *Fetcher[S, R]) ScheduledLenForTest() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.schedule.Len()
}

func (f *Fetcher[S, R]) RequestCountForTest() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *Fetcher[S, R]) NextFetchForTest() (FetchAt, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.schedule.Peek()
}

func (f *Fetcher[S, R]) GenerationForTest(key remotehttp.FetchKey) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[key].Generation
}
