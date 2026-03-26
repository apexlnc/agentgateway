package jwks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/apiclient"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

const configMapKey = "jwks-store"
const jwksStoreComponentLabel = "app.kubernetes.io/component"

func JwksStoreLabelSelector(storePrefix string) string {
	return jwksStoreComponentLabel + "=" + storePrefix
}

func JwksStoreConfigMapLabel(storePrefix string) map[string]string {
	return map[string]string{jwksStoreComponentLabel: storePrefix}
}

// persistedKeysetReader provides an informer-backed read view of persisted
// JWKS ConfigMaps. It is separate from ConfigMapController, which owns writeback.
type persistedKeysetReader struct {
	storePrefix         string
	deploymentNamespace string
	cmCollection        krt.Collection[*corev1.ConfigMap]
}

func newPersistedKeysetReader(client apiclient.Client, storePrefix, deploymentNamespace string, krtOptions krtutil.KrtOptions) *persistedKeysetReader {
	cmCollection := krt.NewFilteredInformer[*corev1.ConfigMap](client,
		kclient.Filter{
			ObjectFilter:  client.ObjectFilter(),
			LabelSelector: JwksStoreLabelSelector(storePrefix)},
		krtOptions.ToOptions("persisted_keyset_reader/ConfigMaps")...)

	return &persistedKeysetReader{
		deploymentNamespace: deploymentNamespace,
		storePrefix:         storePrefix,
		cmCollection:        cmCollection,
	}
}

func JwksFromConfigMap(cm *corev1.ConfigMap) (Keyset, error) {
	jwksStore := cm.Data[configMapKey]

	var keyset Keyset
	if err := json.Unmarshal([]byte(jwksStore), &keyset); err == nil && keyset.RequestKey != "" {
		return keyset, nil
	}

	// Fallback to legacy map format
	var legacy map[string]string
	if err := json.Unmarshal([]byte(jwksStore), &legacy); err != nil {
		return Keyset{}, fmt.Errorf("failed to unmarshal current and legacy formats: %w", err)
	}
	if len(legacy) != 1 {
		return Keyset{}, fmt.Errorf("unexpected legacy jwks payload: expected 1 entry, got %d", len(legacy))
	}

	for uri, jwksJSON := range legacy {
		return Keyset{
			RequestKey: remotehttp.FetchTarget{URL: uri}.Key(),
			URL:        uri,
			JwksJSON:   jwksJSON,
		}, nil
	}

	// unreachable after len==1 check, but satisfies the compiler
	return Keyset{}, errors.New("unexpected legacy jwks state")
}

func RequestKeyFromConfigMap(cm *corev1.ConfigMap) (remotehttp.FetchKey, error) {
	keyset, err := JwksFromConfigMap(cm)
	if err != nil {
		return "", err
	}
	return keyset.RequestKey, nil
}

func JwksConfigMapName(storePrefix string, requestKey remotehttp.FetchKey) string {
	sum := sha256.Sum256([]byte(requestKey))
	return fmt.Sprintf("%s-%s", storePrefix, hex.EncodeToString(sum[:]))
}

func JwksConfigMapNamespacedName(storePrefix, namespace string, requestKey remotehttp.FetchKey) types.NamespacedName {
	return types.NamespacedName{
		Namespace: namespace,
		Name:      JwksConfigMapName(storePrefix, requestKey),
	}
}

func SetJwksInConfigMap(cm *corev1.ConfigMap, keyset Keyset) error {
	b, err := json.Marshal(keyset)
	if err != nil {
		return err
	}
	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	cm.Data[configMapKey] = string(b)
	return nil
}

func (cs *persistedKeysetReader) LoadPersistedKeysets(ctx context.Context) ([]Keyset, error) {
	log := log.FromContext(ctx)

	kube.WaitForCacheSync("JWKS ConfigMaps", ctx.Done(), cs.cmCollection.HasSynced)

	allPersistedJwks := cs.cmCollection.List()
	if len(allPersistedJwks) == 0 {
		return nil, nil
	}

	errs := make([]error, 0)
	keysets := make([]Keyset, 0, len(allPersistedJwks))
	for _, cm := range allPersistedJwks {
		keyset, err := JwksFromConfigMap(cm)
		if err != nil {
			log.Error(err, "error deserializing jwks ConfigMap", "ConfigMap", cm.Name)
			errs = append(errs, err)
			continue
		}
		keysets = append(keysets, keyset)
	}

	return keysets, errors.Join(errs...)
}
