package deployer

import (
	"encoding/json"
	"sync"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
)

var unmarshalLocalConfigOIDCDetector = json.Unmarshal

// oidcRequiredGatewaysCollection is the interface for checking whether a given set of
// resolved AgentgatewayParameters require an OIDC cookie secret. It is used by
// agentgateway_parameters.go to set OIDCCookieSecretName in helm values (GetValues path)
// and by gateway_parameters.go to decide whether to emit the Secret (PostProcessObjects path).
//
// The interface allows Phase 5 (TrafficOIDCGateways KRT collection) to be wired in later
// without changing the calling code.
type oidcRequiredGatewaysCollection interface {
	// resolvedParametersRequireOIDC returns true when the resolved parameters indicate
	// that the gateway needs an OIDC cookie secret generated.
	resolvedParametersRequireOIDC(resolved *resolvedParameters) bool
}

// buildOIDCRequiredGatewaysCollection constructs the concrete collection.
// Currently only rawConfig-based detection is supported; Phase 5 will wire in
// xDS-delivered TrafficOIDC policies via the Inputs struct.
func buildOIDCRequiredGatewaysCollection() oidcRequiredGatewaysCollection {
	return &rawConfigOIDCCollection{
		detectRawConfigUsesLocalOIDC: rawConfigUsesLocalOIDC,
	}
}

// rawConfigOIDCCollection detects OIDC usage by inspecting rawConfig in
// AgentgatewayParameters. This runs inside the existing reconciliation loop and
// memoizes by exact raw JSON content so repeated checks in a reconcile avoid
// re-unmarshalling the same payload.
type rawConfigOIDCCollection struct {
	rawConfigUsageCache          sync.Map
	detectRawConfigUsesLocalOIDC func(raw *apiextensionsv1.JSON) bool
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
	if cached, ok := c.rawConfigUsageCache.Load(cacheKey); ok {
		return cached.(bool)
	}

	detect := c.detectRawConfigUsesLocalOIDC
	if detect == nil {
		detect = rawConfigUsesLocalOIDC
	}

	result := detect(raw)
	cached, _ := c.rawConfigUsageCache.LoadOrStore(cacheKey, result)
	return cached.(bool)
}

func resolvedParametersUseLocalOIDC(resolved *resolvedParameters) bool {
	if resolved == nil {
		return false
	}
	return agentgatewayParametersUseLocalOIDC(resolved.gatewayClassAGWP) ||
		agentgatewayParametersUseLocalOIDC(resolved.gatewayAGWP)
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
	if err := unmarshalLocalConfigOIDCDetector(raw.Raw, &cfg); err != nil {
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
