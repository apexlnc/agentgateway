package jwks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestJwksFromConfigMapAcceptsLegacyPayload(t *testing.T) {
	cm := &corev1.ConfigMap{
		Data: map[string]string{
			configMapKey: `{"https://issuer.example/jwks":"{\"keys\":[]}"}`,
		},
	}

	keyset, err := JwksFromConfigMap(cm)

	assert.NoError(t, err)
	assert.Equal(t, "https://issuer.example/jwks", keyset.URL)
	assert.Equal(t, Request{URL: "https://issuer.example/jwks"}.Key(), keyset.RequestKey)
}

func TestJwksFromConfigMapRejectsMultiEntryLegacyPayload(t *testing.T) {
	cm := &corev1.ConfigMap{
		Data: map[string]string{
			configMapKey: `{"https://a.example/jwks":"{\"keys\":[]}","https://b.example/jwks":"{\"keys\":[]}"}`,
		},
	}

	_, err := JwksFromConfigMap(cm)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 1 entry, got 2")
}

func TestJwksFromConfigMapRejectsEmptyLegacyPayload(t *testing.T) {
	cm := &corev1.ConfigMap{
		Data: map[string]string{
			configMapKey: `{}`,
		},
	}

	_, err := JwksFromConfigMap(cm)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 1 entry, got 0")
}

func TestSetAndReadConfigMapRoundTrip(t *testing.T) {
	original := Keyset{
		RequestKey: Request{URL: "https://issuer.example/jwks"}.Key(),
		URL:        "https://issuer.example/jwks",
		JwksJSON:   `{"keys":[]}`,
	}
	cm := &corev1.ConfigMap{}

	assert.NoError(t, SetJwksInConfigMap(cm, original))

	got, err := JwksFromConfigMap(cm)

	assert.NoError(t, err)
	assert.Equal(t, original.RequestKey, got.RequestKey)
	assert.Equal(t, original.URL, got.URL)
	assert.Equal(t, original.JwksJSON, got.JwksJSON)
}
