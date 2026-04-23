package plugins

import (
	"fmt"

	"k8s.io/apimachinery/pkg/types"

	"github.com/agentgateway/agentgateway/api"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	oidcpkg "github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

const oidcPolicySuffix = ":oidc"

func processOIDCPolicy(
	ctx PolicyCtx,
	oidcCfg *agentgateway.OIDC,
	basePolicyName string,
	policy types.NamespacedName,
	oidcLookup oidcpkg.Lookup,
) (*api.Policy, error) {
	// Always emit a skeleton policy: callers append it even when the lookup
	// fails so status conditions can surface the unresolved state.
	spec := &api.TrafficPolicySpec_OIDC{
		PolicyId:    "policy/" + policy.String(),
		ClientId:    oidcCfg.ClientID,
		RedirectUri: oidcCfg.RedirectURI,
		Scopes:      oidcCfg.Scopes,
	}

	oidcPolicy := &api.Policy{
		Key:  basePolicyName + oidcPolicySuffix,
		Name: TypedResourceFromName(wellknown.AgentgatewayPolicyGVK.Kind, policy),
		Kind: &api.Policy_Traffic{
			Traffic: &api.TrafficPolicySpec{
				Kind: &api.TrafficPolicySpec_Oidc{Oidc: spec},
			},
		},
	}

	if oidcLookup == nil {
		return oidcPolicy, fmt.Errorf("oidc lookup is not configured")
	}

	owner := buildOIDCOwner(policy, oidcCfg)
	provider, err := oidcLookup.ResolveForOwner(ctx.Krt, owner)
	if err != nil {
		return oidcPolicy, fmt.Errorf("oidc provider for %s/%s not available: %w", policy.Namespace, policy.Name, err)
	}
	if provider == nil {
		return oidcPolicy, fmt.Errorf("oidc provider for %s/%s not yet fetched", policy.Namespace, policy.Name)
	}

	spec.Issuer = provider.IssuerURL
	spec.AuthorizationEndpoint = provider.AuthorizationEndpoint
	spec.TokenEndpoint = provider.TokenEndpoint
	spec.JwksInline = provider.JwksJSON
	// ClientSecret is delivered out-of-band via env var, never via xDS.

	logger.Debug("generated oidc policy",
		"policy", basePolicyName,
		"agentgateway_policy", oidcPolicy.Name)

	return oidcPolicy, nil
}

func buildOIDCOwner(policy types.NamespacedName, oidcCfg *agentgateway.OIDC) oidcpkg.RemoteOidcOwner {
	return oidcpkg.RemoteOidcOwner{
		ID: oidcpkg.OidcOwnerID{
			Namespace: policy.Namespace,
			Name:      policy.Name,
			Path:      "spec.traffic.oidc",
		},
		DefaultNamespace: policy.Namespace,
		Config:           *oidcCfg,
		TTL:              oidcpkg.TTLForOIDC(*oidcCfg),
	}
}
