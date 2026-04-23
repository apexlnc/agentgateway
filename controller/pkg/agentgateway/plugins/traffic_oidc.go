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

const (
	oidcConfigTokenEndpointAuthMethodClientSecretBasic   = "ClientSecretBasic"
	oidcConfigTokenEndpointAuthMethodClientSecretPost    = "ClientSecretPost"
	oidcProviderTokenEndpointAuthMethodClientSecretBasic = "client_secret_basic"
	oidcProviderTokenEndpointAuthMethodClientSecretPost  = "client_secret_post"
)

func processOIDCPolicy(
	ctx PolicyCtx,
	oidcCfg *agentgateway.OIDC,
	basePolicyName string,
	policy types.NamespacedName,
	oidcLookup oidcpkg.Lookup,
) (*api.Policy, error) {
	tokenEndpointAuth, err := configuredOIDCTokenEndpointAuth(oidcCfg)
	if err != nil {
		return nil, err
	}

	// Always emit a skeleton policy: callers append it even when the lookup
	// fails so status conditions can surface the unresolved state.
	spec := &api.TrafficPolicySpec_OIDC{
		PolicyId:          oidcpkg.PolicyIDForPolicy(policy.Namespace, policy.Name).String(),
		TokenEndpointAuth: tokenEndpointAuth,
		ClientId:          oidcCfg.ClientID,
		RedirectUri:       oidcCfg.RedirectURI,
		Scopes:            oidcCfg.Scopes,
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

	owner, ok := oidcpkg.PolicyOIDCLookupOwner(policy.Namespace, policy.Name, oidcCfg)
	if !ok {
		return oidcPolicy, fmt.Errorf("oidc lookup owner is not configured")
	}
	provider, err := oidcLookup.ResolveForOwner(ctx.Krt, owner)
	if err != nil {
		return oidcPolicy, fmt.Errorf("oidc provider for %s/%s not available: %w", policy.Namespace, policy.Name, err)
	}
	if provider == nil {
		return oidcPolicy, fmt.Errorf("oidc provider for %s/%s not yet fetched", policy.Namespace, policy.Name)
	}

	tokenEndpointAuth, err = resolvedOIDCTokenEndpointAuth(oidcCfg, provider)
	if err != nil {
		return oidcPolicy, fmt.Errorf("oidc token endpoint auth for %s/%s is invalid: %w", policy.Namespace, policy.Name, err)
	}

	spec.Issuer = provider.IssuerURL
	spec.AuthorizationEndpoint = provider.AuthorizationEndpoint
	spec.TokenEndpoint = provider.TokenEndpoint
	spec.TokenEndpointAuth = tokenEndpointAuth
	spec.JwksInline = provider.JwksJSON
	// ClientSecret is delivered out-of-band via env var, never via xDS.

	logger.Debug("generated oidc policy",
		"policy", basePolicyName,
		"agentgateway_policy", oidcPolicy.Name)

	return oidcPolicy, nil
}

func configuredOIDCTokenEndpointAuth(oidcCfg *agentgateway.OIDC) (api.TrafficPolicySpec_OIDC_TokenEndpointAuth, error) {
	if oidcCfg.TokenEndpointAuthMethod == nil {
		return api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC, nil
	}

	switch *oidcCfg.TokenEndpointAuthMethod {
	case oidcConfigTokenEndpointAuthMethodClientSecretBasic:
		return api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC, nil
	case oidcConfigTokenEndpointAuthMethodClientSecretPost:
		return api.TrafficPolicySpec_OIDC_CLIENT_SECRET_POST, nil
	default:
		return api.TrafficPolicySpec_OIDC_TOKEN_ENDPOINT_AUTH_UNSPECIFIED, fmt.Errorf(
			"unsupported tokenEndpointAuthMethod %q",
			*oidcCfg.TokenEndpointAuthMethod,
		)
	}
}

func resolvedOIDCTokenEndpointAuth(
	oidcCfg *agentgateway.OIDC,
	provider *oidcpkg.DiscoveredProvider,
) (api.TrafficPolicySpec_OIDC_TokenEndpointAuth, error) {
	if oidcCfg.TokenEndpointAuthMethod != nil {
		return configuredOIDCTokenEndpointAuth(oidcCfg)
	}
	return discoveredOIDCTokenEndpointAuth(provider.TokenEndpointAuthMethodsSupported)
}

func discoveredOIDCTokenEndpointAuth(
	methods []string,
) (api.TrafficPolicySpec_OIDC_TokenEndpointAuth, error) {
	if len(methods) == 0 {
		return api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC, nil
	}

	for _, method := range methods {
		if method == oidcProviderTokenEndpointAuthMethodClientSecretBasic {
			return api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC, nil
		}
	}
	for _, method := range methods {
		if method == oidcProviderTokenEndpointAuthMethodClientSecretPost {
			return api.TrafficPolicySpec_OIDC_CLIENT_SECRET_POST, nil
		}
	}

	return api.TrafficPolicySpec_OIDC_TOKEN_ENDPOINT_AUTH_UNSPECIFIED, fmt.Errorf(
		"token endpoint auth methods must include %q or %q",
		oidcProviderTokenEndpointAuthMethodClientSecretBasic,
		oidcProviderTokenEndpointAuthMethodClientSecretPost,
	)
}
