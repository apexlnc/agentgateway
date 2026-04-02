package plugins

import (
	"fmt"
	"strings"

	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/api"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/utils"
	"github.com/agentgateway/agentgateway/controller/pkg/utils/kubeutils"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

type listenerOIDCMode struct {
	hasGatewayPhase bool
	hasRoutePhase   bool
}

type listenerRef struct {
	gateway  types.NamespacedName
	listener string
}

func processOIDCAuthenticationPolicy(
	ctx PolicyCtx,
	sourcePolicy *agentgateway.AgentgatewayPolicy,
	authn *agentgateway.OIDCAuthentication,
	policyPhase *agentgateway.PolicyPhase,
	basePolicyName string,
	policy types.NamespacedName,
) (*api.Policy, error) {
	if err := validateOIDCListenerModes(ctx, sourcePolicy); err != nil {
		return nil, err
	}

	provider, err := resolveOIDCProvider(ctx, policy, authn)
	if err != nil {
		return nil, err
	}
	var providerBackend *api.BackendReference
	if authn.Discovery != nil && authn.Discovery.BackendRef != nil {
		providerBackend, err = buildBackendRef(ctx, *authn.Discovery.BackendRef, policy.Namespace)
		if err != nil {
			return nil, fmt.Errorf("resolve oidc provider backend: %w", err)
		}
	}
	clientSecret, err := resolveOIDCClientSecret(ctx, policy.Namespace, authn.ClientSecretRef)
	if err != nil {
		return nil, err
	}

	tokenEndpointAuth, err := translateOIDCTokenEndpointAuth(provider.TokenEndpointAuth)
	if err != nil {
		return nil, err
	}

	policyKey := basePolicyName + oidcPolicySuffix
	oidcPolicy := &api.Policy{
		Key:  policyKey,
		Name: TypedResourceFromName(wellknown.AgentgatewayPolicyGVK.Kind, policy),
		Kind: &api.Policy_Traffic{
			Traffic: &api.TrafficPolicySpec{
				Phase: phase(policyPhase),
				Kind: &api.TrafficPolicySpec_Oidc{
					Oidc: &api.TrafficPolicySpec_OIDC{
						Issuer:                provider.Issuer,
						AuthorizationEndpoint: provider.AuthorizationEndpoint,
						TokenEndpoint:         provider.TokenEndpoint,
						TokenEndpointAuth:     tokenEndpointAuth,
						JwksInline:            provider.JwksInline,
						ClientId:              authn.ClientID,
						ClientSecret:          clientSecret,
						RedirectUri:           authn.RedirectURI,
						Scopes:                authn.Scopes,
						PolicyId:              "policy/" + policyKey,
						ProviderBackend:       providerBackend,
					},
				},
			},
		},
	}

	return oidcPolicy, nil
}

func translateOIDCTokenEndpointAuth(value string) (api.TrafficPolicySpec_OIDC_TokenEndpointAuth, error) {
	switch value {
	case "clientSecretBasic":
		return api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC, nil
	case "clientSecretPost":
		return api.TrafficPolicySpec_OIDC_CLIENT_SECRET_POST, nil
	default:
		return api.TrafficPolicySpec_OIDC_TOKEN_ENDPOINT_AUTH_UNSPECIFIED, fmt.Errorf("unsupported oidc token endpoint auth method %q", value)
	}
}

func resolveOIDCProvider(
	ctx PolicyCtx,
	policy types.NamespacedName,
	authn *agentgateway.OIDCAuthentication,
) (oidc.ProviderConfig, error) {
	source, err := oidc.BuildProviderSource(ctx.Krt, ctx.Resolver, policy, "", authn)
	if err != nil {
		return oidc.ProviderConfig{}, err
	}

	cmName := oidc.ProviderConfigMapNamespacedName(ctx.Collections.SystemNamespace, oidc.DefaultProviderStorePrefix, source.RequestKey)
	cm := ptr.Flatten(krt.FetchOne(ctx.Krt, ctx.Collections.ConfigMaps, krt.FilterObjectName(cmName)))
	if cm == nil {
		return oidc.ProviderConfig{}, fmt.Errorf("oidc provider ConfigMap %s is not available", cmName)
	}

	cfg, err := oidc.ProviderConfigFromConfigMap(cm)
	if err != nil {
		return oidc.ProviderConfig{}, fmt.Errorf("decode oidc provider ConfigMap %s: %w", cmName, err)
	}
	if cfg.RequestKey != source.RequestKey {
		return oidc.ProviderConfig{}, fmt.Errorf("oidc provider ConfigMap %s request key mismatch", cmName)
	}
	return cfg, nil
}

func resolveOIDCClientSecret(ctx PolicyCtx, namespace string, ref corev1.LocalObjectReference) (string, error) {
	secretName := types.NamespacedName{Namespace: namespace, Name: ref.Name}
	secret, err := kubeutils.GetSecret(ctx.Collections.Secrets, ctx.Krt, ref.Name, namespace)
	if err != nil {
		return "", fmt.Errorf("oidc client secret %s not found", secretName)
	}
	clientSecret, ok := kubeutils.GetSecretValueExact(secret, wellknown.ClientSecret)
	if !ok || strings.TrimSpace(clientSecret) == "" {
		return "", fmt.Errorf("oidc client secret %s missing %q entry", secretName, wellknown.ClientSecret)
	}
	return clientSecret, nil
}

func validateOIDCListenerModes(ctx PolicyCtx, current *agentgateway.AgentgatewayPolicy) error {
	currentListeners := oidcAffectedListeners(ctx, current)
	if len(currentListeners) == 0 {
		return nil
	}

	modes := map[listenerRef]listenerOIDCMode{}
	for _, policy := range ctx.Collections.AgentgatewayPolicies.List() {
		if policy.Spec.Traffic == nil || policy.Spec.Traffic.OIDCAuthentication == nil {
			continue
		}
		listeners := oidcAffectedListeners(ctx, policy)
		for _, listener := range listeners {
			mode := modes[listener]
			if ptr.OrEmpty(policy.Spec.Traffic.Phase) == agentgateway.PolicyPhasePreRouting {
				mode.hasGatewayPhase = true
			} else {
				mode.hasRoutePhase = true
			}
			modes[listener] = mode
		}
	}

	for _, listener := range currentListeners {
		mode := modes[listener]
		if mode.hasGatewayPhase && mode.hasRoutePhase {
			return fmt.Errorf("listener '%s/%s/%s' cannot mix gateway-phase oidc with route-phase oidc", listener.gateway.Namespace, listener.gateway.Name, listener.listener)
		}
	}
	return nil
}

func oidcAffectedListeners(ctx PolicyCtx, policy *agentgateway.AgentgatewayPolicy) []listenerRef {
	var listeners []listenerRef
	for _, target := range policy.Spec.TargetRefs {
		gk := schema.GroupKind{Group: string(target.Group), Kind: string(target.Kind)}
		switch gk {
		case wellknown.GatewayGVK.GroupKind():
			gatewayNN := types.NamespacedName{Namespace: policy.Namespace, Name: string(target.Name)}
			gateway := ptr.Flatten(krt.FetchOne(ctx.Krt, ctx.Collections.Gateways, krt.FilterObjectName(gatewayNN)))
			if gateway == nil {
				continue
			}
			if target.SectionName != nil {
				listeners = append(listeners, listenerRef{gateway: gatewayNN, listener: string(*target.SectionName)})
				continue
			}
			for _, listener := range gateway.Spec.Listeners {
				listeners = append(listeners, listenerRef{gateway: gatewayNN, listener: string(listener.Name)})
			}
		case wellknown.HTTPRouteGVK.GroupKind(), wellknown.GRPCRouteGVK.GroupKind(), wellknown.TCPRouteGVK.GroupKind(), wellknown.TLSRouteGVK.GroupKind():
			routeNN := types.NamespacedName{Namespace: policy.Namespace, Name: string(target.Name)}
			for _, ref := range routeParentListeners(ctx, gk, routeNN) {
				listeners = append(listeners, ref)
			}
		}
	}
	return listeners
}

func routeParentListeners(ctx PolicyCtx, gk schema.GroupKind, routeNN types.NamespacedName) []listenerRef {
	routeObject := utilsTypedNamespacedName(routeNN, gk.Kind)
	gateways := ctx.References.LookupGatewaysForTarget(ctx.Krt, routeObject).UnsortedList()
	if len(gateways) == 0 {
		return nil
	}

	parentRefs := routeParentRefs(ctx, gk, routeNN)
	var listeners []listenerRef
	for _, gatewayNN := range gateways {
		matched := false
		for _, parentRef := range parentRefs {
			if !parentRefMatchesGateway(parentRef, routeNN.Namespace, gatewayNN) {
				continue
			}
			matched = true
			if parentRef.SectionName != nil {
				listeners = append(listeners, listenerRef{gateway: gatewayNN, listener: string(*parentRef.SectionName)})
				continue
			}
			listeners = append(listeners, gatewayAllListeners(ctx, gatewayNN)...)
		}
		if !matched {
			listeners = append(listeners, gatewayAllListeners(ctx, gatewayNN)...)
		}
	}
	return listeners
}

func routeParentRefs(ctx PolicyCtx, gk schema.GroupKind, routeNN types.NamespacedName) []gwv1.ParentReference {
	switch gk {
	case wellknown.HTTPRouteGVK.GroupKind():
		route := ptr.Flatten(krt.FetchOne(ctx.Krt, ctx.Collections.HTTPRoutes, krt.FilterObjectName(routeNN)))
		if route != nil {
			return route.Spec.ParentRefs
		}
	case wellknown.GRPCRouteGVK.GroupKind():
		route := ptr.Flatten(krt.FetchOne(ctx.Krt, ctx.Collections.GRPCRoutes, krt.FilterObjectName(routeNN)))
		if route != nil {
			return route.Spec.ParentRefs
		}
	case wellknown.TCPRouteGVK.GroupKind():
		route := ptr.Flatten(krt.FetchOne(ctx.Krt, ctx.Collections.TCPRoutes, krt.FilterObjectName(routeNN)))
		if route != nil {
			return route.Spec.ParentRefs
		}
	case wellknown.TLSRouteGVK.GroupKind():
		route := ptr.Flatten(krt.FetchOne(ctx.Krt, ctx.Collections.TLSRoutes, krt.FilterObjectName(routeNN)))
		if route != nil {
			return route.Spec.ParentRefs
		}
	}
	return nil
}

func gatewayAllListeners(ctx PolicyCtx, gatewayNN types.NamespacedName) []listenerRef {
	gateway := ptr.Flatten(krt.FetchOne(ctx.Krt, ctx.Collections.Gateways, krt.FilterObjectName(gatewayNN)))
	if gateway == nil {
		return nil
	}
	listeners := make([]listenerRef, 0, len(gateway.Spec.Listeners))
	for _, listener := range gateway.Spec.Listeners {
		listeners = append(listeners, listenerRef{gateway: gatewayNN, listener: string(listener.Name)})
	}
	return listeners
}

func parentRefMatchesGateway(parent gwv1.ParentReference, defaultNamespace string, gatewayNN types.NamespacedName) bool {
	if ptr.OrDefault(parent.Group, gwv1.Group(wellknown.GatewayGroup)) != gwv1.Group(wellknown.GatewayGroup) {
		return false
	}
	if ptr.OrDefault(parent.Kind, gwv1.Kind(wellknown.GatewayKind)) != gwv1.Kind(wellknown.GatewayKind) {
		return false
	}
	namespace := string(ptr.OrDefault(parent.Namespace, gwv1.Namespace(defaultNamespace)))
	return namespace == gatewayNN.Namespace && string(parent.Name) == gatewayNN.Name
}

func utilsTypedNamespacedName(nn types.NamespacedName, kind string) utils.TypedNamespacedName {
	return utils.TypedNamespacedName{
		NamespacedName: nn,
		Kind:           kind,
	}
}
