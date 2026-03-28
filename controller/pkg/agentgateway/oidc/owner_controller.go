package oidc

import (
	"context"

	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"k8s.io/client-go/tools/cache"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/apiclient"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

type OwnerController struct {
	inputs          OwnerControllerInputs
	apiClient       apiclient.Client
	owners          krt.Collection[ProviderOwner]
	providers       krt.Collection[ProviderSource]
	providerChanges chan ProviderSource
	waitForSync     []cache.InformerSynced
}

type OwnerControllerInputs struct {
	AgentgatewayPolicies krt.Collection[*agentgateway.AgentgatewayPolicy]
	Resolver             Resolver
	KrtOpts              krtutil.KrtOptions
}

var polLogger = logging.New("oidc_owner_controller")

func NewOwnerController(apiClient apiclient.Client, inputs OwnerControllerInputs) *OwnerController {
	polLogger.Info("creating oidc owner controller")
	return &OwnerController{
		inputs:          inputs,
		apiClient:       apiClient,
		providerChanges: make(chan ProviderSource, 64),
	}
}

func (o *OwnerController) Init(ctx context.Context) {
	o.owners = krt.NewManyCollection(o.inputs.AgentgatewayPolicies, func(kctx krt.HandlerContext, p *agentgateway.AgentgatewayPolicy) []ProviderOwner {
		return OwnersFromPolicy(p)
	}, o.inputs.KrtOpts.ToOptions("PolicyOIDCProviders")...)
	o.providers = krt.NewCollection(o.owners, func(kctx krt.HandlerContext, owner ProviderOwner) *ProviderSource {
		return o.resolveOwner(kctx, owner)
	}, o.inputs.KrtOpts.ToOptions("ResolvedOIDCProviders")...)

	o.waitForSync = []cache.InformerSynced{
		o.inputs.AgentgatewayPolicies.HasSynced,
	}
}

func (o *OwnerController) Start(ctx context.Context) error {
	polLogger.Info("waiting for cache to sync")
	o.apiClient.Core().WaitForCacheSync(
		"kube AgentgatewayPolicy syncer",
		ctx.Done(),
		o.waitForSync...,
	)

	polLogger.Info("starting oidc owner controller")
	o.providers.Register(func(event krt.Event[ProviderSource]) {
		switch event.Event {
		case controllers.EventAdd, controllers.EventUpdate:
			if event.New != nil {
				o.providerChanges <- *event.New
			}
		case controllers.EventDelete:
			deleted := *event.Old
			deleted.Deleted = true
			o.providerChanges <- deleted
		}
	})

	<-ctx.Done()
	return nil
}

func (o *OwnerController) NeedLeaderElection() bool {
	return true
}

func (o *OwnerController) ProviderChanges() <-chan ProviderSource {
	return o.providerChanges
}

func (o *OwnerController) resolveOwner(krtctx krt.HandlerContext, owner ProviderOwner) *ProviderSource {
	resolved, err := o.inputs.Resolver.ResolveOwner(krtctx, owner)
	if err != nil {
		polLogger.Error("error generating oidc discovery url or tls options", "error", err)
		return nil
	}

	return &ProviderSource{
		OwnerKey:   resolved.OwnerID,
		Issuer:     resolved.Issuer,
		RequestKey: resolved.Target.Key,
		Target:     resolved.Target.Target,
		TLSConfig:  resolved.Target.TLSConfig,
		TTL:        resolved.TTL,
	}
}
