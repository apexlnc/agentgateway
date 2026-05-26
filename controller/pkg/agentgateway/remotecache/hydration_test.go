package remotecache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type hydrationTestResult struct {
	Key remotehttp.FetchKey
}

func (r hydrationTestResult) RemoteRequestKey() remotehttp.FetchKey { return r.Key }
func (r hydrationTestResult) RemoteFetchedAt() time.Time            { return time.Time{} }

func entry(name string) Entry[hydrationTestResult] {
	payload := hydrationTestResult{Key: "test-key"}
	return Entry[hydrationTestResult]{
		NamespacedName: types.NamespacedName{Name: name},
		Payload:        &payload,
	}
}

func TestBestHydrationEntryPrefersCanonical(t *testing.T) {
	other := entry("other")
	canonical := entry("canonical")

	best := BestHydrationEntry([]Entry[hydrationTestResult]{other, canonical}, "canonical")
	require.Equal(t, "canonical", best.GetName())
}

func TestBestHydrationEntryFallsBackToFirstWhenNoCanonical(t *testing.T) {
	first := entry("a")
	second := entry("b")

	best := BestHydrationEntry([]Entry[hydrationTestResult]{first, second}, "canonical")
	require.Equal(t, "a", best.GetName())
}

func TestBestHydrationEntryEmptyReturnsZero(t *testing.T) {
	best := BestHydrationEntry[hydrationTestResult](nil, "canonical")
	require.Equal(t, Entry[hydrationTestResult]{}, best)
}
