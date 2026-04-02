package agentoidcstore

import (
	"context"
	"fmt"

	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"k8s.io/apimachinery/pkg/types"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/plugins"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

var policyLogger = logging.New("oidc_store_policy_controller")

type PolicyController struct {
	agw           *plugins.AgwCollections
	sources       krt.Collection[oidc.ProviderSource]
	sourceChanges chan oidc.ProviderSource
	resolver      remotehttp.Resolver
}

func NewPolicyController(agw *plugins.AgwCollections, resolver remotehttp.Resolver) *PolicyController {
	return &PolicyController{
		agw:           agw,
		sourceChanges: make(chan oidc.ProviderSource),
		resolver:      resolver,
	}
}

func (c *PolicyController) Init(_ context.Context) {
	c.sources = krt.NewManyCollection(c.agw.AgentgatewayPolicies, func(kctx krt.HandlerContext, policy *agentgateway.AgentgatewayPolicy) []oidc.ProviderSource {
		source, err := c.buildProviderSource(kctx, policy)
		if err != nil {
			policyLogger.Error("error building oidc provider source", "policy", fmt.Sprintf("%s/%s", policy.Namespace, policy.Name), "error", err)
			return nil
		}
		if source == nil {
			return nil
		}
		return []oidc.ProviderSource{*source}
	}, c.agw.KrtOpts.ToOptions("OidcProviderSources")...)
}

func (c *PolicyController) Start(ctx context.Context) error {
	policyLogger.Info("starting oidc store policy controller")
	c.sources.Register(func(event krt.Event[oidc.ProviderSource]) {
		switch event.Event {
		case controllers.EventAdd, controllers.EventUpdate:
			c.sourceChanges <- *event.New
		case controllers.EventDelete:
			deleted := *event.Old
			deleted.Deleted = true
			c.sourceChanges <- deleted
		}
	})

	<-ctx.Done()
	return nil
}

func (c *PolicyController) NeedLeaderElection() bool {
	return true
}

func (c *PolicyController) SourceChanges() chan oidc.ProviderSource {
	return c.sourceChanges
}

func (c *PolicyController) buildProviderSource(
	kctx krt.HandlerContext,
	policy *agentgateway.AgentgatewayPolicy,
) (*oidc.ProviderSource, error) {
	if policy.Spec.Traffic == nil || policy.Spec.Traffic.OIDCAuthentication == nil {
		return nil, nil
	}

	authn := policy.Spec.Traffic.OIDCAuthentication
	owner := oidc.PolicyOwnerKey(policy.Namespace, policy.Name, "traffic.oidcAuthentication")
	source, err := oidc.BuildProviderSource(
		kctx,
		c.resolver,
		types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name},
		owner,
		authn,
	)
	if err != nil {
		return nil, err
	}
	return &source, nil
}
