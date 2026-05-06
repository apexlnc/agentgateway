package remotecache

import (
	"reflect"

	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// ResultRecord wraps a fetched remote artifact so it has a stable KRT key.
// The payload remains the domain result type; the wrapper is only the
// KRT-visible publication envelope used by the fetch runtime and persistence
// reconciler.
type ResultRecord[R Result] struct {
	Payload R
}

func (r ResultRecord[R]) ResourceName() string {
	return string(r.Payload.RemoteRequestKey())
}

func (r ResultRecord[R]) Equals(other ResultRecord[R]) bool {
	return reflect.DeepEqual(r.Payload, other.Payload)
}

// Results is the KRT-visible store of successfully fetched remote artifacts.
// The fetcher is still imperative for HTTP, retry and TTL scheduling, but its
// output is published as a normal KRT collection instead of a private cache
// plus custom fanout.
type Results[R Result] struct {
	collection krt.StaticCollection[ResultRecord[R]]
}

// NewResults constructs an empty, already-synced fetched-result collection.
func NewResults[R Result](opts ...krt.CollectionOption) *Results[R] {
	return &Results[R]{
		collection: krt.NewStaticCollection(alwaysSynced{}, nil, opts...),
	}
}

func (r *Results[R]) Collection() krt.Collection[ResultRecord[R]] {
	return r.collection
}

func (r *Results[R]) Get(key remotehttp.FetchKey) (R, bool) {
	var zero R
	obj := r.collection.GetKey(string(key))
	if obj == nil {
		return zero, false
	}
	return obj.Payload, true
}

func (r *Results[R]) Put(result R) {
	r.collection.UpdateObject(ResultRecord[R]{Payload: result})
}

func (r *Results[R]) Delete(key remotehttp.FetchKey) bool {
	_, existed := r.Get(key)
	if existed {
		r.collection.DeleteObject(string(key))
	}
	return existed
}

func (r *Results[R]) Keys() []remotehttp.FetchKey {
	objects := r.collection.List()
	keys := make([]remotehttp.FetchKey, 0, len(objects))
	for _, obj := range objects {
		keys = append(keys, obj.Payload.RemoteRequestKey())
	}
	return keys
}

func (r *Results[R]) Reset(results []R) {
	records := make([]ResultRecord[R], 0, len(results))
	for _, result := range results {
		records = append(records, ResultRecord[R]{Payload: result})
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
