package remotecache

import (
	"reflect"

	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// FetchedRecord wraps a fetched remote artifact so it has a stable KRT key.
// The payload remains the domain result type; the wrapper is only the
// KRT-visible publication envelope used by the fetch runtime and persistence
// reconciler.
type FetchedRecord[R Result] struct {
	Payload R
}

func (r FetchedRecord[R]) ResourceName() string {
	return string(r.Payload.RemoteRequestKey())
}

func (r FetchedRecord[R]) Equals(other FetchedRecord[R]) bool {
	return reflect.DeepEqual(r.Payload, other.Payload)
}

// FetchedResults is the KRT-visible store of successfully fetched remote
// artifacts. The fetcher is still imperative for HTTP, retry and TTL
// scheduling, but its output is published as a normal KRT collection instead
// of a private cache plus custom fanout.
type FetchedResults[R Result] struct {
	collection krt.StaticCollection[FetchedRecord[R]]
}

// NewFetchedResults constructs an empty, already-synced fetched-result collection.
func NewFetchedResults[R Result](opts ...krt.CollectionOption) *FetchedResults[R] {
	return &FetchedResults[R]{
		collection: krt.NewStaticCollection[FetchedRecord[R]](alwaysSynced{}, nil, opts...),
	}
}

func (r *FetchedResults[R]) Collection() krt.Collection[FetchedRecord[R]] {
	return r.collection
}

func (r *FetchedResults[R]) Get(key remotehttp.FetchKey) (R, bool) {
	var zero R
	obj := r.collection.GetKey(string(key))
	if obj == nil {
		return zero, false
	}
	return obj.Payload, true
}

func (r *FetchedResults[R]) Put(result R) {
	r.collection.UpdateObject(FetchedRecord[R]{Payload: result})
}

func (r *FetchedResults[R]) Delete(key remotehttp.FetchKey) bool {
	_, existed := r.Get(key)
	if existed {
		r.collection.DeleteObject(string(key))
	}
	return existed
}

func (r *FetchedResults[R]) DeleteObjects(filter func(FetchedRecord[R]) bool) {
	r.collection.DeleteObjects(filter)
}

func (r *FetchedResults[R]) Reset(results []R) {
	records := make([]FetchedRecord[R], 0, len(results))
	for _, result := range results {
		records = append(records, FetchedRecord[R]{Payload: result})
	}
	r.collection.Reset(records)
}

type alwaysSynced struct{}

func (alwaysSynced) HasSynced() bool { return true }

func (alwaysSynced) WaitUntilSynced(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return false
	default:
		return true
	}
}
