package deployer

import (
	"encoding/json"
	"sync"

	"istio.io/istio/pkg/ptr"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	agwplugins "github.com/agentgateway/agentgateway/controller/pkg/agentgateway/plugins"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

// oidcRequiredGatewaysCollection is the interface for checking whether a given set of
// resolved AgentgatewayParameters require an OIDC cookie secret. It is used by
// agentgateway_parameters.go to set OIDCCookieSecretName in helm values (GetValues path)
// and by gateway_parameters.go to decide whether to emit the Secret (PostProcessObjects path).
type oidcRequiredGatewaysCollection interface {
	// gatewayRequiresOIDC returns true when the gateway needs an OIDC cookie
	// secret generated, either because local rawConfig uses OIDC or because an
	// attached AgentgatewayPolicy carries spec.traffic.oidc.
	gatewayRequiresOIDC(gw *gwv1.Gateway, resolved *resolvedParameters) bool
}

// buildOIDCRequiredGatewaysCollection constructs the concrete collection used
// by the deployer to decide whether a Gateway needs a managed OIDC cookie
// secret.
func buildOIDCRequiredGatewaysCollection(inputs *Inputs) oidcRequiredGatewaysCollection {
	var agwCollections *agwplugins.AgwCollections
	if inputs != nil {
		agwCollections = inputs.AgwCollections
	}
	return &rawConfigOIDCCollection{
		detectRawConfigUsesLocalOIDC: rawConfigUsesLocalOIDC,
		agwCollections:               agwCollections,
	}
}

// rawConfigOIDCCollection detects OIDC usage from two sources:
// 1. AgentgatewayParameters rawConfig
// 2. attached AgentgatewayPolicy.spec.traffic.oidc policies
//
// Raw-config checks memoize by exact JSON payload so repeated checks in a
// reconcile avoid re-unmarshalling the same content.
type rawConfigOIDCCollection struct {
	rawConfigUsageMu             sync.Mutex
	rawConfigUsageCache          map[string]bool
	detectRawConfigUsesLocalOIDC func(raw *apiextensionsv1.JSON) bool
	agwCollections               *agwplugins.AgwCollections
}

func (c *rawConfigOIDCCollection) gatewayRequiresOIDC(gw *gwv1.Gateway, resolved *resolvedParameters) bool {
	return c.resolvedParametersRequireOIDC(resolved) || c.gatewayUsesAttachedPolicyOIDC(gw)
}

func (c *rawConfigOIDCCollection) resolvedParametersRequireOIDC(resolved *resolvedParameters) bool {
	if resolved == nil {
		return false
	}
	return c.agentgatewayParametersUseLocalOIDC(resolved.gatewayClassAGWP) ||
		c.agentgatewayParametersUseLocalOIDC(resolved.gatewayAGWP)
}

func (c *rawConfigOIDCCollection) agentgatewayParametersUseLocalOIDC(agwp *agentgateway.AgentgatewayParameters) bool {
	if agwp == nil {
		return false
	}
	return c.memoizedRawConfigUsesLocalOIDC(agwp.Spec.AgentgatewayParametersConfigs.RawConfig)
}

func (c *rawConfigOIDCCollection) memoizedRawConfigUsesLocalOIDC(raw *apiextensionsv1.JSON) bool {
	if raw == nil || len(raw.Raw) == 0 {
		return false
	}

	cacheKey := string(raw.Raw)
	c.rawConfigUsageMu.Lock()
	if c.rawConfigUsageCache == nil {
		c.rawConfigUsageCache = make(map[string]bool)
	}
	if cached, ok := c.rawConfigUsageCache[cacheKey]; ok {
		c.rawConfigUsageMu.Unlock()
		return cached
	}
	c.rawConfigUsageMu.Unlock()

	detect := c.detectRawConfigUsesLocalOIDC
	if detect == nil {
		detect = rawConfigUsesLocalOIDC
	}

	result := detect(raw)
	c.rawConfigUsageMu.Lock()
	defer c.rawConfigUsageMu.Unlock()
	if cached, ok := c.rawConfigUsageCache[cacheKey]; ok {
		return cached
	}
	c.rawConfigUsageCache[cacheKey] = result
	return result
}

func (c *rawConfigOIDCCollection) gatewayUsesAttachedPolicyOIDC(gw *gwv1.Gateway) bool {
	if c == nil || c.agwCollections == nil || c.agwCollections.AgentgatewayPolicies == nil || gw == nil {
		return false
	}

	for _, policy := range c.agwCollections.AgentgatewayPolicies.List() {
		if !policyUsesOIDC(policy) {
			continue
		}
		if policyStatusTargetsGateway(gw, policy, c.agwCollections.ControllerName) {
			return true
		}
	}

	return false
}

func policyUsesOIDC(policy *agentgateway.AgentgatewayPolicy) bool {
	return policy != nil && policy.Spec.Traffic != nil && policy.Spec.Traffic.OIDC != nil
}

func policyStatusTargetsGateway(
	gw *gwv1.Gateway,
	policy *agentgateway.AgentgatewayPolicy,
	controllerName string,
) bool {
	if gw == nil || policy == nil {
		return false
	}

	for _, ancestor := range policy.Status.Ancestors {
		if controllerName != "" && string(ancestor.ControllerName) != controllerName {
			continue
		}
		ref := ancestor.AncestorRef
		group := ptr.OrDefault(ref.Group, gwv1.Group(""))
		kind := ptr.OrDefault(ref.Kind, gwv1.Kind(""))
		namespace := ptr.OrDefault(ref.Namespace, gwv1.Namespace(policy.Namespace))
		if string(group) != wellknown.GatewayGVK.Group || string(kind) != wellknown.GatewayGVK.Kind {
			continue
		}
		if string(ref.Name) == gw.Name && string(namespace) == gw.Namespace {
			return true
		}
	}
	return false
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
