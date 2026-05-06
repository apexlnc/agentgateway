package jwks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil/krttest"
)

func TestAddKeysetToFetcher(t *testing.T) {
	expected := testSharedJwksRequest("https://test/jwks")

	f := NewFetcher(NewFetchedResults())
	f.AddOrUpdate(expected)

	fetch, ok := f.NextFetchForTest()
	assert.True(t, ok)
	assert.Equal(t, expected.RequestKey, fetch.RequestKey)
	assert.Equal(t, 1, f.RequestCountForTest())
}

func TestRemoveKeysetFromFetcher(t *testing.T) {
	source := testSharedJwksRequest("https://test/jwks")
	results := NewFetchedResults()
	f := NewFetcher(results)

	f.AddOrUpdate(source)
	seedJwksResultsForTest(results, source.RequestKey, source.Target.URL)

	f.Remove(source.RequestKey)

	assert.Equal(t, 0, f.RequestCountForTest())
	_, ok := results.Get(source.RequestKey)
	assert.False(t, ok)
}

func TestRemoveKeysetClearsResultsEvenWithoutRequest(t *testing.T) {
	source := testSharedJwksRequest("https://test/jwks")
	results := NewFetchedResults()
	f := NewFetcher(results)
	seedJwksResultsForTest(results, source.RequestKey, source.Target.URL)

	f.Remove(source.RequestKey)

	_, ok := results.Get(source.RequestKey)
	assert.False(t, ok, "fetched result should be cleared even when request was not tracked")
}

func TestRetireKeysetKeepsResultThenSweptOnSuccessfulFetch(t *testing.T) {
	ctx := t.Context()
	oldSource := testSharedJwksRequest("https://test/old-jwks")
	newSource := testSharedJwksRequest("https://test/new-jwks")

	results := NewFetchedResults()
	f := NewFetcher(results)
	f.AddOrUpdate(oldSource)
	seedJwksResultsForTest(results, oldSource.RequestKey, oldSource.Target.URL)

	f.Retire(oldSource.RequestKey)

	assert.Equal(t, 0, f.RequestCountForTest(), "retired key should be removed from requests")
	_, inResults := results.Get(oldSource.RequestKey)
	assert.True(t, inResults, "retired key should remain in fetched results")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, sampleJWKS)
	}))
	defer backend.Close()
	newSource.Target.URL = backend.URL
	newSource.RequestKey = newSource.Target.Key()

	f.AddOrUpdate(newSource)
	go f.MaybeFetch(ctx)

	keyset := awaitStoredKeyset(t, results, newSource.RequestKey)
	assert.Equal(t, sampleJWKS, keyset.JwksJSON)

	_, inResults = results.Get(oldSource.RequestKey)
	assert.False(t, inResults, "retired key should be swept after successful fetch")
}

func TestSuccessfulJwksFetch(t *testing.T) {
	ctx := t.Context()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, sampleJWKS)
	}))
	defer backend.Close()

	results := NewFetchedResults()
	f := NewFetcher(results)
	source := testSharedJwksRequest(backend.URL)
	f.AddOrUpdate(source)

	go f.MaybeFetch(ctx)

	keyset := awaitStoredKeyset(t, results, source.RequestKey)
	assert.Equal(t, sampleJWKS, keyset.JwksJSON)
}

func testSharedJwksRequest(requestURL string) SharedJwksRequest {
	target := remotehttp.FetchTarget{URL: requestURL}
	return SharedJwksRequest{
		RequestKey: target.Key(),
		Target:     target,
		TTL:        5 * time.Minute,
	}
}

func seedJwksResultsForTest(results *JwksResults, requestKey remotehttp.FetchKey, url string) {
	results.Put(Keyset{
		RequestKey: requestKey,
		URL:        url,
		JwksJSON:   `{"keys":[]}`,
	})
}

func awaitStoredKeyset(t *testing.T, results *JwksResults, requestKey remotehttp.FetchKey) Keyset {
	t.Helper()

	var keyset Keyset
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var ok bool
		keyset, ok = results.Get(requestKey)
		assert.True(c, ok)
	}, krttest.EventuallyTimeout, krttest.EventuallyPoll)

	return keyset
}

// sampleJWKS is a minimal valid JWKS so the fetcher's non-empty-keys check
// accepts it. Uses an `oct` key to avoid generating real RSA material.
var sampleJWKS = `{"keys":[{"kty":"oct","k":"AAECAwQFBgc"}]}`
