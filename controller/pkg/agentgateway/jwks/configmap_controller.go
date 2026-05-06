package jwks

import (
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
	"github.com/agentgateway/agentgateway/controller/pkg/apiclient"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

// PersistenceController synchronizes fetched JWKS keysets to persisted ConfigMaps.
type PersistenceController struct {
	*remotecache.PersistenceController[Keyset, PersistedEntry]
}

func NewPersistenceController(apiClient apiclient.Client, storePrefix, deploymentNamespace string, store *Store, persistedEntries *PersistedEntries) *PersistenceController {
	logger := logging.New("jwks_store_persistence_controller")
	logger.Info("creating jwks store persistence controller")

	opts := remotecache.PersistenceControllerOptions[Keyset, PersistedEntry]{
		ApiClient:            apiClient,
		DeploymentNamespace:  deploymentNamespace,
		ControllerName:       "JwksStorePersistenceController",
		Results:              store.FetchedResults().Collection(),
		Entries:              persistedEntries.Collection(),
		EntriesForRequestKey: persistedEntries.EntriesForRequestKey,
		Serialize:            SetJwksInConfigMap,
		NameFunc:             persistedEntries.ConfigMapName,
		LabelFunc:            persistedEntries.ConfigMapLabels,
		LabelSelector:        persistedEntries.LabelSelector,
		StoreHasSynced:       store.HasSynced,
		Logger:               logger,
	}

	return &PersistenceController{
		PersistenceController: remotecache.NewPersistenceController(opts),
	}
}
