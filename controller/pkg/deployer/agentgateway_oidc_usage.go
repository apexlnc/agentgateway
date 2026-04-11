package deployer

import (
	"encoding/json"

	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	agwplugins "github.com/agentgateway/agentgateway/controller/pkg/agentgateway/plugins"
)

type oidcGatewayUsage struct {
	Gateway types.NamespacedName
}

func (u oidcGatewayUsage) ResourceName() string {
	return u.Gateway.String()
}

func (u oidcGatewayUsage) Equals(other oidcGatewayUsage) bool {
	return u.Gateway == other.Gateway
}

func buildOIDCRequiredGatewaysCollection(
	inputs *Inputs,
	agwParams krt.Collection[*agentgateway.AgentgatewayParameters],
) krt.Collection[oidcGatewayUsage] {
	if inputs == nil || inputs.AgwCollections == nil {
		return nil
	}
	var trafficOIDCGatewaysByGateway krt.Index[string, agwplugins.GatewayTrafficOIDC]
	if inputs.TrafficOIDCGateways != nil {
		trafficOIDCGatewaysByGateway = krt.NewIndex(inputs.TrafficOIDCGateways, "gateway", func(gateway agwplugins.GatewayTrafficOIDC) []string {
			return []string{gateway.Gateway.String()}
		})
	}

	return krt.NewCollection(
		inputs.AgwCollections.Gateways,
		func(kctx krt.HandlerContext, gw *gwv1.Gateway) *oidcGatewayUsage {
			if !gatewayUsesController(kctx, inputs.AgwCollections.GatewayClasses, gw, inputs.AgentgatewayControllerName) {
				return nil
			}

			key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
			if trafficOIDCGatewaysByGateway != nil {
				if len(krt.Fetch(kctx, inputs.TrafficOIDCGateways, krt.FilterIndex(trafficOIDCGatewaysByGateway, key.String()))) != 0 {
					return &oidcGatewayUsage{Gateway: key}
				}
			}

			resolved, err := resolveParametersWithLookup(
				gw,
				func(name string) *gwv1.GatewayClass {
					return ptr.Flatten(krt.FetchOne(kctx, inputs.AgwCollections.GatewayClasses, krt.FilterKey(name)))
				},
				func(name, namespace string) *agentgateway.AgentgatewayParameters {
					return ptr.Flatten(krt.FetchOne(kctx, agwParams, krt.FilterObjectName(types.NamespacedName{
						Namespace: namespace,
						Name:      name,
					})))
				},
			)
			if err == nil && resolvedParametersUseLocalOIDC(resolved) {
				return &oidcGatewayUsage{Gateway: key}
			}

			return nil
		},
		inputs.AgwCollections.KrtOpts.ToOptions("deployer/OIDCRequiredGateways")...,
	)
}

func (g *agentgatewayParametersHelmValuesGenerator) gatewayRequiresOIDCCookieSecret(gw *gwv1.Gateway) bool {
	if g == nil || g.oidcRequiredGateways == nil {
		return false
	}
	return g.oidcRequiredGateways.GetKey(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}.String()) != nil
}

func (g *agentgatewayParametersHelmValuesGenerator) RegisterGatewayChangeHandlers(queue controllers.Queue) {
	if g == nil || g.oidcRequiredGateways == nil {
		return
	}
	g.oidcRequiredGateways.Register(func(event krt.Event[oidcGatewayUsage]) {
		queue.Add(event.Latest().Gateway)
	})
}

func gatewayUsesController(
	kctx krt.HandlerContext,
	gatewayClasses krt.Collection[*gwv1.GatewayClass],
	gw *gwv1.Gateway,
	controllerName string,
) bool {
	gwc := ptr.Flatten(krt.FetchOne(kctx, gatewayClasses, krt.FilterKey(string(gw.Spec.GatewayClassName))))
	return gwc != nil && string(gwc.Spec.ControllerName) == controllerName
}

func resolvedParametersUseLocalOIDC(resolved *resolvedParameters) bool {
	if resolved == nil {
		return false
	}
	return agentgatewayParametersUseLocalOIDC(resolved.gatewayClassAGWP) || agentgatewayParametersUseLocalOIDC(resolved.gatewayAGWP)
}

func agentgatewayParametersUseLocalOIDC(agwp *agentgateway.AgentgatewayParameters) bool {
	if agwp == nil {
		return false
	}
	return rawConfigUsesLocalOIDC(agwp.Spec.AgentgatewayParametersConfigs.RawConfig)
}

func rawConfigUsesLocalOIDC(raw *apiextensionsv1.JSON) bool {
	if raw == nil || len(raw.Raw) == 0 {
		return false
	}

	var cfg localConfigOIDCDetector
	if err := json.Unmarshal(raw.Raw, &cfg); err != nil {
		return false
	}
	return cfg.usesOIDC()
}

type localConfigOIDCDetector struct {
	Binds    []localBindOIDCDetector           `json:"binds,omitempty"`
	Policies []localTargetedPolicyOIDCDetector `json:"policies,omitempty"`
	LLM      *localPolicyRootOIDCDetector      `json:"llm,omitempty"`
	MCP      *localPolicyRootOIDCDetector      `json:"mcp,omitempty"`
}

func (c localConfigOIDCDetector) usesOIDC() bool {
	for _, bind := range c.Binds {
		if bind.usesOIDC() {
			return true
		}
	}
	for _, policy := range c.Policies {
		if policy.Policy.usesOIDC() {
			return true
		}
	}
	return (c.LLM != nil && c.LLM.usesOIDC()) || (c.MCP != nil && c.MCP.usesOIDC())
}

type localBindOIDCDetector struct {
	Listeners []localListenerOIDCDetector `json:"listeners,omitempty"`
}

func (b localBindOIDCDetector) usesOIDC() bool {
	for _, listener := range b.Listeners {
		if listener.usesOIDC() {
			return true
		}
	}
	return false
}

type localListenerOIDCDetector struct {
	Policies *localPolicyOIDCDetector `json:"policies,omitempty"`
	Routes   []localRouteOIDCDetector `json:"routes,omitempty"`
}

func (l localListenerOIDCDetector) usesOIDC() bool {
	if l.Policies != nil && l.Policies.usesOIDC() {
		return true
	}
	for _, route := range l.Routes {
		if route.usesOIDC() {
			return true
		}
	}
	return false
}

type localRouteOIDCDetector struct {
	Policies *localPolicyOIDCDetector `json:"policies,omitempty"`
}

func (r localRouteOIDCDetector) usesOIDC() bool {
	return r.Policies != nil && r.Policies.usesOIDC()
}

type localTargetedPolicyOIDCDetector struct {
	Policy localPolicyOIDCDetector `json:"policy"`
}

type localPolicyRootOIDCDetector struct {
	Policies *localPolicyOIDCDetector `json:"policies,omitempty"`
}

func (p localPolicyRootOIDCDetector) usesOIDC() bool {
	return p.Policies != nil && p.Policies.usesOIDC()
}

type localPolicyOIDCDetector struct {
	OIDC json.RawMessage `json:"oidc,omitempty"`
}

func (p localPolicyOIDCDetector) usesOIDC() bool {
	return len(p.OIDC) != 0
}
