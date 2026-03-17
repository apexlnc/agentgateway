package jwks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestPlanConfigMapSyncKeepsCanonicalConfigMap(t *testing.T) {
	keyset := Keyset{
		RequestKey: Request{URL: "https://issuer.example/jwks"}.Key(),
		URL:        "https://issuer.example/jwks",
		JwksJSON:   `{"keys":[]}`,
	}
	plan := planConfigMapSync(keyset.RequestKey, nil, DefaultJwksStorePrefix, func(requestKey RequestKey) (Keyset, bool) {
		if requestKey == keyset.RequestKey {
			return keyset, true
		}
		return Keyset{}, false
	})

	if assert.NotNil(t, plan.keyset) {
		assert.Equal(t, keyset, *plan.keyset)
	}
	assert.Equal(t, JwksConfigMapName(DefaultJwksStorePrefix, keyset.RequestKey), plan.upsertName)
	assert.Empty(t, plan.deleteNames)
}

func TestPlanConfigMapSyncDeletesInactiveConfigMap(t *testing.T) {
	keyset := Keyset{
		RequestKey: Request{URL: "https://issuer.example/jwks"}.Key(),
		URL:        "https://issuer.example/jwks",
		JwksJSON:   `{"keys":[]}`,
	}
	cmName := JwksConfigMapName(DefaultJwksStorePrefix, keyset.RequestKey)
	existingCm := configMapWithKeyset(t, cmName, "agentgateway-system", keyset)

	plan := planConfigMapSync(keyset.RequestKey, []*corev1.ConfigMap{existingCm}, DefaultJwksStorePrefix, func(RequestKey) (Keyset, bool) {
		return Keyset{}, false
	})

	assert.Nil(t, plan.keyset)
	assert.Empty(t, plan.upsertName)
	assert.Equal(t, []string{cmName}, plan.deleteNames)
}

func TestPlanConfigMapSyncNoopsWhenConfigMapIsAlreadyGone(t *testing.T) {
	requestKey := Request{URL: "https://issuer.example/jwks"}.Key()

	plan := planConfigMapSync(requestKey, nil, DefaultJwksStorePrefix, func(RequestKey) (Keyset, bool) {
		return Keyset{}, false
	})

	assert.Nil(t, plan.keyset)
	assert.Empty(t, plan.upsertName)
	assert.Empty(t, plan.deleteNames)
}

func TestPlanConfigMapSyncDeletesNonCanonicalConfigMapsForActiveRequest(t *testing.T) {
	keyset := Keyset{
		RequestKey: Request{URL: "https://issuer.example/jwks"}.Key(),
		URL:        "https://issuer.example/jwks",
		JwksJSON:   `{"keys":[]}`,
	}
	canonicalName := JwksConfigMapName(DefaultJwksStorePrefix, keyset.RequestKey)
	legacyName := "jwks-store-legacy-name"
	plan := planConfigMapSync(
		keyset.RequestKey,
		[]*corev1.ConfigMap{
			configMapWithKeyset(t, canonicalName, "agentgateway-system", keyset),
			configMapWithKeyset(t, legacyName, "agentgateway-system", keyset),
		},
		DefaultJwksStorePrefix,
		func(requestKey RequestKey) (Keyset, bool) {
			if requestKey == keyset.RequestKey {
				return keyset, true
			}
			return Keyset{}, false
		},
	)

	if assert.NotNil(t, plan.keyset) {
		assert.Equal(t, keyset, *plan.keyset)
	}
	assert.Equal(t, canonicalName, plan.upsertName)
	assert.Equal(t, []string{legacyName}, plan.deleteNames)
}

func configMapWithKeyset(t *testing.T, name, namespace string, keyset Keyset) *corev1.ConfigMap {
	t.Helper()

	cm := &corev1.ConfigMap{
		Data: map[string]string{},
	}
	cm.Name = name
	cm.Namespace = namespace
	if err := SetJwksInConfigMap(cm, keyset); err != nil {
		t.Fatalf("SetJwksInConfigMap() error = %v", err)
	}
	return cm
}
