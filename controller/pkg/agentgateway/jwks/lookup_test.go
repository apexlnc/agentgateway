package jwks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/test"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type staticLookupResolver struct {
	resolved *ResolvedJwksRequest
	err      error
}

type alwaysSynced struct{}

func (r staticLookupResolver) ResolveOwner(krt.HandlerContext, RemoteJwksOwner) (*ResolvedJwksRequest, error) {
	return r.resolved, r.err
}

func (alwaysSynced) WaitUntilSynced(stop <-chan struct{}) bool {
	return true
}

func (alwaysSynced) HasSynced() bool {
	return true
}

func TestLookupFailsClosedWhenKeysetIsMissing(t *testing.T) {
	stop := test.NewStop(t)
	request := Request{URL: "https://issuer.example/jwks"}
	lookupIndex := NewLookup(
		krt.NewStaticCollection[*corev1.ConfigMap](alwaysSynced{}, nil),
		staticLookupResolver{resolved: &ResolvedJwksRequest{
			Endpoint: remotehttp.ResolvedEndpoint{
				Key:     request.Key(),
				Request: request,
			},
		}},
		DefaultJwksStorePrefix,
		"agentgateway-system",
	)
	lookupImpl := lookupIndex.(*lookup)
	lookupImpl.cache.keysets.WaitUntilSynced(stop)

	_, err := lookupIndex.InlineForOwner(krt.TestingDummyContext{}, RemoteJwksOwner{})

	assert.EqualError(t, err, `jwks keyset for "https://issuer.example/jwks" isn't available (not yet fetched or fetch failed)`)
}

func TestLookupReturnsPersistedKeyset(t *testing.T) {
	stop := test.NewStop(t)
	request := Request{URL: "https://issuer.example/jwks"}
	keyset := Keyset{
		RequestKey: request.Key(),
		URL:        request.URL,
		JwksJSON:   `{"keys":[]}`,
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      JwksConfigMapName(DefaultJwksStorePrefix, request.Key()),
			Namespace: "agentgateway-system",
		},
	}
	assert.NoError(t, SetJwksInConfigMap(cm, keyset))

	lookupIndex := NewLookup(
		krt.NewStaticCollection[*corev1.ConfigMap](alwaysSynced{}, []*corev1.ConfigMap{cm}),
		staticLookupResolver{resolved: &ResolvedJwksRequest{
			Endpoint: remotehttp.ResolvedEndpoint{
				Key:     request.Key(),
				Request: request,
			},
		}},
		DefaultJwksStorePrefix,
		"agentgateway-system",
	)
	lookupImpl := lookupIndex.(*lookup)
	lookupImpl.cache.keysets.WaitUntilSynced(stop)

	inline, err := lookupIndex.InlineForOwner(krt.TestingDummyContext{}, RemoteJwksOwner{})

	assert.NoError(t, err)
	assert.Equal(t, keyset.JwksJSON, inline)
}
