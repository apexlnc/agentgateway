package oidc

import (
	"context"
	"encoding/json"
	"errors"

	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/apiclient"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

type configMapSyncer struct {
	storePrefix         string
	deploymentNamespace string
	cmCollection        krt.Collection[*corev1.ConfigMap]
}

func NewConfigMapSyncer(client apiclient.Client, storePrefix, deploymentNamespace string, krtOptions krtutil.KrtOptions) *configMapSyncer {
	cmCollection := krt.NewFilteredInformer[*corev1.ConfigMap](client,
		kclient.Filter{
			ObjectFilter:  client.ObjectFilter(),
			Namespace:     deploymentNamespace,
			LabelSelector: ProviderStoreLabelSelector(storePrefix),
		},
		krtOptions.ToOptions("oidc_config_map_syncer/ConfigMaps")...,
	)

	return &configMapSyncer{
		storePrefix:         storePrefix,
		deploymentNamespace: deploymentNamespace,
		cmCollection:        cmCollection,
	}
}

func ProviderConfigFromConfigMap(cm *corev1.ConfigMap) (ProviderConfig, error) {
	raw := cm.Data[ProviderConfigMapKey]
	var cfg ProviderConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return ProviderConfig{}, err
	}
	return cfg, cfg.Validate()
}

func SetProviderConfigInConfigMap(cm *corev1.ConfigMap, cfg ProviderConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[ProviderConfigMapKey] = string(raw)
	return nil
}

func (cs *configMapSyncer) LoadProviderConfigs(ctx context.Context) (map[remotehttp.FetchKey]ProviderConfig, error) {
	log := log.FromContext(ctx)
	allPersistedProviders := cs.cmCollection.List()
	if len(allPersistedProviders) == 0 {
		return nil, nil
	}

	configs := make(map[remotehttp.FetchKey]ProviderConfig, len(allPersistedProviders))
	var errs []error
	for _, cm := range allPersistedProviders {
		cfg, err := ProviderConfigFromConfigMap(cm)
		if err != nil {
			log.Error(err, "error deserializing oidc provider ConfigMap", "ConfigMap", cm.Name)
			errs = append(errs, err)
			continue
		}
		configs[cfg.RequestKey] = cfg
	}

	return configs, errors.Join(errs...)
}
