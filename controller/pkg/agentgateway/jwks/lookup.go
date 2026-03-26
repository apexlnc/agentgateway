package jwks

import (
	"fmt"

	"istio.io/istio/pkg/kube/krt"
	corev1 "k8s.io/api/core/v1"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type Lookup interface {
	InlineForOwner(krtctx krt.HandlerContext, owner RemoteJwksOwner) (string, error)
}

type lookup struct {
	resolver Resolver
	cache    *keysetCache
}

func NewLookup(configMaps krt.Collection[*corev1.ConfigMap], resolver Resolver, storePrefix, storeNamespace string) Lookup {
	return &lookup{
		resolver: resolver,
		cache:    newKeysetCache(configMaps, storePrefix, storeNamespace),
	}
}

func (l *lookup) InlineForOwner(krtctx krt.HandlerContext, owner RemoteJwksOwner) (string, error) {
	resolved, err := l.resolver.ResolveOwner(krtctx, owner)
	if err != nil {
		return "", err
	}

	keyset, ok := l.cache.Get(krtctx, resolved.Target.Key)
	if !ok {
		return "", fmt.Errorf("jwks keyset for %q isn't available (not yet fetched or fetch failed)", resolved.Target.Target.URL)
	}
	return keyset.JwksJSON, nil
}

// keysetCache provides an in-memory view of persisted JWKS keysets. It is
// hydrated by the ConfigMap informer, so lookup does not depend on raw
// ConfigMap fetches or persistence naming details.
type keysetCache struct {
	storePrefix string
	keysets     krt.Collection[cachedKeyset]
}

type cachedKeyset struct {
	Name string
	Keyset
}

func (c cachedKeyset) ResourceName() string {
	return c.Name
}

func (c cachedKeyset) Equals(other cachedKeyset) bool {
	return c.Name == other.Name && c.Keyset == other.Keyset
}

func newKeysetCache(configMaps krt.Collection[*corev1.ConfigMap], storePrefix, storeNamespace string) *keysetCache {
	keysets := krt.NewCollection(configMaps, func(krtctx krt.HandlerContext, cm *corev1.ConfigMap) *cachedKeyset {
		if cm.Namespace != storeNamespace {
			return nil
		}

		keyset, err := JwksFromConfigMap(cm)
		if err != nil {
			return nil
		}

		cached := cachedKeyset{Name: cm.Name, Keyset: keyset}
		return &cached
	})

	return &keysetCache{
		storePrefix: storePrefix,
		keysets:     keysets,
	}
}

func (c *keysetCache) Get(krtctx krt.HandlerContext, requestKey remotehttp.FetchKey) (Keyset, bool) {
	keyset := krt.FetchOne(krtctx, c.keysets, krt.FilterKey(JwksConfigMapName(c.storePrefix, requestKey)))
	if keyset == nil {
		return Keyset{}, false
	}
	return keyset.Keyset, true
}
