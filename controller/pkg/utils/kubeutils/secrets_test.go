package kubeutils

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetSecretValueExactPreservesWhitespace(t *testing.T) {
	t.Parallel()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-secret",
		},
		Data: map[string][]byte{
			"key": []byte("  value with spaces  "),
		},
	}

	value, found := GetSecretValueExact(secret, "key")
	if !found {
		t.Fatal("expected secret value to be found")
	}
	if value != "  value with spaces  " {
		t.Fatalf("unexpected exact secret value %q", value)
	}
}

func TestGetSecretValueExactRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-secret",
		},
		Data: map[string][]byte{
			"key": {0xff, 0xfe, 0xfd},
		},
	}

	if value, found := GetSecretValueExact(secret, "key"); found || value != "" {
		t.Fatalf("expected invalid UTF-8 to be rejected, got found=%v value=%q", found, value)
	}
}
