package syncer

import (
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/ir"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/plugins"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/translator"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

type PolicyStatusCollections = map[schema.GroupKind]krt.StatusCollection[controllers.Object, any]

// CollectPolicyReferences collects backend references from all plugins without
// building policies. This allows the reference index to be fully populated
// (including PolicyAttachments from e.g. ext_proc backendRefs) before policies
// like BackendTLSPolicy run and need to look up gateways for backends.
func CollectPolicyReferences(agwPlugins plugins.AgwPlugin, references plugins.ReferenceIndex, krtopts krtutil.KrtOptions) krt.Collection[*plugins.PolicyAttachment] {
	var allReferences []krt.Collection[*plugins.PolicyAttachment]
	for _, plugin := range agwPlugins.ContributesPolicies {
		if plugin.BuildReferences != nil {
			refs := plugin.BuildReferences(plugins.PolicyPluginInput{References: references})
			if refs != nil {
				allReferences = append(allReferences, refs)
			}
		}
	}
	return krt.JoinCollection(allReferences, krtopts.ToOptions("PolicyReferences")...)
}

// BuildPolicies builds all policies using the provided (fully-populated) reference index.
func BuildPolicies(
	agwPlugins plugins.AgwPlugin,
	references plugins.ReferenceIndex,
	krtopts krtutil.KrtOptions,
) (krt.Collection[plugins.AgwPolicy], krt.Collection[ir.AgwResource], PolicyStatusCollections) {
	var allPolicies []krt.Collection[plugins.AgwPolicy]
	policyStatusMap := PolicyStatusCollections{}
	for gvk, plugin := range agwPlugins.ContributesPolicies {
		status, col := plugin.Build(plugins.PolicyPluginInput{References: references})
		allPolicies = append(allPolicies, col)
		if status != nil {
			policyStatusMap[gvk] = status
		}
	}
	joinPolicies := krt.JoinCollection(allPolicies, krtopts.ToOptions("JoinPolicies")...)

	allPoliciesCol := krt.NewCollection(joinPolicies, func(ctx krt.HandlerContext, i plugins.AgwPolicy) *ir.AgwResource {
		return ptr.Of(translator.ToResourceForGateway(*i.Gateway, i))
	}, krtopts.ToOptions("AllPolicies")...)

	return joinPolicies, allPoliciesCol, policyStatusMap
}

func GatewayTrafficOIDCCollection(
	gateways krt.Collection[*gwv1.Gateway],
	policies krt.Collection[plugins.AgwPolicy],
	krtopts krtutil.KrtOptions,
) krt.Collection[plugins.GatewayTrafficOIDC] {
	oidcPoliciesByGateway := krt.NewIndex(policies, "gatewayTrafficOIDC", func(policy plugins.AgwPolicy) []string {
		if policy.Gateway == nil || policy.Policy.GetTraffic() == nil || policy.Policy.GetTraffic().GetOidc() == nil {
			return nil
		}
		return []string{policy.Gateway.String()}
	})

	return krt.NewCollection(gateways, func(ctx krt.HandlerContext, gateway *gwv1.Gateway) *plugins.GatewayTrafficOIDC {
		key := types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}
		if len(krt.Fetch(ctx, policies, krt.FilterIndex(oidcPoliciesByGateway, key.String()))) == 0 {
			return nil
		}
		return ptr.Of(plugins.GatewayTrafficOIDC{Gateway: key})
	}, krtopts.ToOptions("GatewayTrafficOIDC")...)
}
