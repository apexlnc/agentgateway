package remotefetch

import (
	"container/heap"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

const (
	InitialRetryDelay = 100 * time.Millisecond
	MaxRetryDelay     = 15 * time.Second
	MaxRetryShift     = 30
	ClientTimeout     = 10 * time.Second
)

type Entry struct {
	At           time.Time
	RequestKey   remotehttp.FetchKey
	Generation   uint64
	RetryAttempt int
	index        int
}

type entryHeap []*Entry

func (s entryHeap) Len() int           { return len(s) }
func (s entryHeap) Less(i, j int) bool { return s[i].At.Before(s[j].At) }
func (s entryHeap) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
	s[i].index = i
	s[j].index = j
}

func (s *entryHeap) Push(x any) {
	entry := x.(*Entry)
	entry.index = len(*s)
	*s = append(*s, entry)
}

func (s *entryHeap) Pop() any {
	old := *s
	n := len(old)
	entry := old[n-1]
	entry.index = -1
	old[n-1] = nil
	*s = old[:n-1]
	return entry
}

type Schedule struct {
	heap      entryHeap
	scheduled map[remotehttp.FetchKey]*Entry
}

func NewSchedule() *Schedule {
	s := &Schedule{
		heap:      make(entryHeap, 0),
		scheduled: make(map[remotehttp.FetchKey]*Entry),
	}
	heap.Init(&s.heap)
	return s
}

func (s *Schedule) Len() int {
	return len(s.heap)
}

func (s *Schedule) Peek() *Entry {
	if len(s.heap) == 0 {
		return nil
	}
	return s.heap[0]
}

func (s *Schedule) PopDue(now time.Time) []Entry {
	var due []Entry
	for {
		next := s.Peek()
		if next == nil || next.At.After(now) {
			return due
		}
		entry := heap.Pop(&s.heap).(*Entry)
		delete(s.scheduled, entry.RequestKey)
		due = append(due, *entry)
	}
}

func (s *Schedule) Schedule(requestKey remotehttp.FetchKey, generation uint64, at time.Time, retryAttempt int) {
	if scheduled := s.scheduled[requestKey]; scheduled != nil {
		scheduled.At = at
		scheduled.Generation = generation
		scheduled.RetryAttempt = retryAttempt
		heap.Fix(&s.heap, scheduled.index)
		return
	}

	entry := &Entry{
		At:           at,
		RequestKey:   requestKey,
		Generation:   generation,
		RetryAttempt: retryAttempt,
		index:        -1,
	}
	heap.Push(&s.heap, entry)
	s.scheduled[requestKey] = entry
}

func (s *Schedule) Remove(requestKey remotehttp.FetchKey) {
	if scheduled := s.scheduled[requestKey]; scheduled != nil {
		heap.Remove(&s.heap, scheduled.index)
		delete(s.scheduled, requestKey)
	}
}

func NextRetryDelay(retryAttempt int) time.Duration {
	shift := min(retryAttempt+1, MaxRetryShift)

	next := InitialRetryDelay * time.Duration(1<<shift)
	if next > MaxRetryDelay {
		return MaxRetryDelay
	}
	return next
}

func MakeClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Timeout: ClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			DisableKeepAlives: true,
		},
	}
}

func DrainTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func Signal(wake chan<- struct{}) {
	select {
	case wake <- struct{}{}:
	default:
	}
}
