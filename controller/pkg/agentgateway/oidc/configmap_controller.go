package oidc

import (
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
	"github.com/agentgateway/agentgateway/controller/pkg/apiclient"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

// PersistenceController synchronizes fetched OIDC providers to persisted ConfigMaps.
type PersistenceController struct {
	*remotecache.PersistenceController[DiscoveredProvider, PersistedEntry]
}

// PersistenceControllerOptions configures NewPersistenceController.
type PersistenceControllerOptions struct {
	APIClient           apiclient.Client
	StorePrefix         string
	DeploymentNamespace string
	Store               *Store
	PersistedEntries    *PersistedEntries
}

func NewPersistenceController(opts PersistenceControllerOptions) *PersistenceController {
	logger := logging.New("oidc_store_persistence_controller")
	logger.Info("creating oidc store persistence controller")

	controllerOpts := remotecache.PersistenceControllerOptions[DiscoveredProvider, PersistedEntry]{
		ApiClient:            opts.APIClient,
		DeploymentNamespace:  opts.DeploymentNamespace,
		ControllerName:       "OidcStorePersistenceController",
		Results:              opts.Store.FetchedResults().Collection(),
		Entries:              opts.PersistedEntries.Collection(),
		EntriesForRequestKey: opts.PersistedEntries.EntriesForRequestKey,
		Serialize:            SetProviderInConfigMap,
		NameFunc:             opts.PersistedEntries.ConfigMapName,
		LabelFunc:            opts.PersistedEntries.ConfigMapLabels,
		LabelSelector:        opts.PersistedEntries.LabelSelector,
		StoreHasSynced:       opts.Store.HasSynced,
		Logger:               logger,
	}

	return &PersistenceController{
		PersistenceController: remotecache.NewPersistenceController(controllerOpts),
	}
}
