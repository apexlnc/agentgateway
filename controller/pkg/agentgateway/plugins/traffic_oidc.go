package plugins

import (
	"fmt"
	"strings"

	"istio.io/istio/pkg/slices"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/api"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

// oidcPolicyIDForPolicyKey returns the canonical xDS PolicyId for an emitted
// xDS Policy key.
func oidcPolicyIDForPolicyKey(key string) string {
	return "policy/" + key
}

func processOIDCPolicy(
	ctx PolicyCtx,
	oidcCfg *agentgateway.OIDC,
	policyPhase *agentgateway.PolicyPhase,
	policy types.NamespacedName,
	basePolicyName string,
	oidcLookup oidc.Lookup,
) (*api.Policy, error) {
	if oidcLookup == nil {
		return nil, fmt.Errorf("oidc lookup is not configured")
	}

	owner, ok := oidc.PolicyOIDCLookupOwner(policy.Namespace, policy.Name, oidcCfg)
	if !ok {
		return nil, fmt.Errorf("could not derive OIDC owner for policy")
	}

	provider, err := oidcLookup.ResolveForOwner(ctx.Krt, owner)
	if err != nil {
		return nil, err
	}

	if provider.JwksInline == "" {
		return nil, fmt.Errorf("oidc provider for %q has no jwks_inline (fetch pending)", oidcCfg.IssuerURL)
	}

	var clientSecret string
	if oidcCfg.ClientSecret != nil {
		secret, err := resolveOIDCClientSecret(ctx, policy.Namespace, oidcCfg)
		if err != nil {
			return nil, err
		}
		clientSecret = secret
	}

	tokenAuth, err := resolveOIDCTokenEndpointAuth(oidcCfg, clientSecret != "")
	if err != nil {
		return nil, err
	}

	var providerBackend *api.BackendReference
	if oidcCfg.BackendRef != nil {
		providerBackend, err = BuildBackendRef(ctx, *oidcCfg.BackendRef, policy.Namespace)
		if err != nil {
			return nil, fmt.Errorf("oidc backendRef: %w", err)
		}
	}

	key := basePolicyName + oidcPolicySuffix
	return &api.Policy{
		Key:  key,
		Name: TypedResourceFromName(wellknown.AgentgatewayPolicyGVK.Kind, policy),
		Kind: &api.Policy_Traffic{
			Traffic: &api.TrafficPolicySpec{
				Phase: phase(policyPhase),
				Kind: &api.TrafficPolicySpec_Oidc{
					Oidc: &api.TrafficPolicySpec_OIDC{
						PolicyId:                          oidcPolicyIDForPolicyKey(key),
						Issuer:                            provider.IssuerURL,
						AuthorizationEndpoint:             provider.AuthorizationEndpoint,
						TokenEndpoint:                     provider.TokenEndpoint,
						JwksInline:                        provider.JwksInline,
						ClientId:                          oidcCfg.ClientID,
						ClientSecret:                      clientSecret,
						RedirectUri:                       oidcCfg.RedirectURI,
						Scopes:                            normalizedOIDCScopes(oidcCfg.Scopes),
						TokenEndpointAuth:                 tokenAuth,
						TokenEndpointAuthMethodsSupported: provider.TokenEndpointAuthMethodsSupported,
						ProviderBackend:                   providerBackend,
					},
				},
			},
		},
	}, nil
}

func normalizedOIDCScopes(input []string) []string {
	return slices.FilterDuplicates(append([]string{"openid"}, input...))
}

func resolveOIDCClientSecret(ctx PolicyCtx, policyNamespace string, oidcCfg *agentgateway.OIDC) (string, error) {
	if oidcCfg.ClientSecret == nil {
		return "", nil
	}

	// OIDC clientSecret is always a Kubernetes Secret; resolve it through the
	// shared credential resolver so it shares the same fetch path (and any
	// injected resolver chain) as the other credential-bearing policies.
	data, err := ctx.ResolveCredentialRef(
		agentgateway.LocalSecretObjectRef{Name: gwv1.ObjectName(oidcCfg.ClientSecret.Name)},
		policyNamespace,
	)
	if err != nil {
		return "", fmt.Errorf("oidc clientSecret %q: %w", oidcCfg.ClientSecret.Name, err)
	}

	// An empty clientSecret would silently switch us onto the public-client
	// auth path, so reject a missing or whitespace-only value explicitly.
	value := strings.TrimSpace(string(data[wellknown.ClientSecret]))
	if value == "" {
		return "", fmt.Errorf("oidc clientSecret %q is missing or has empty %q value", oidcCfg.ClientSecret.Name, wellknown.ClientSecret)
	}
	return value, nil
}

// resolveOIDCTokenEndpointAuth returns the user's explicit override, validating
// its method/clientSecret pairing at apply time. With no override it returns
// UNSPECIFIED, deferring method selection to the dataplane, which resolves it
// from the IdP-advertised methods shipped in TokenEndpointAuthMethodsSupported.
func resolveOIDCTokenEndpointAuth(
	oidcCfg *agentgateway.OIDC,
	hasClientSecret bool,
) (api.TrafficPolicySpec_OIDC_TokenEndpointAuth, error) {
	if oidcCfg.TokenEndpointAuthMethod != nil {
		return configuredOIDCTokenEndpointAuth(oidcCfg, hasClientSecret)
	}
	return api.TrafficPolicySpec_OIDC_TOKEN_ENDPOINT_AUTH_UNSPECIFIED, nil
}

func configuredOIDCTokenEndpointAuth(
	oidcCfg *agentgateway.OIDC,
	hasClientSecret bool,
) (api.TrafficPolicySpec_OIDC_TokenEndpointAuth, error) {
	switch *oidcCfg.TokenEndpointAuthMethod {
	case agentgateway.OIDCTokenEndpointAuthMethodClientSecretBasic:
		if !hasClientSecret {
			return api.TrafficPolicySpec_OIDC_TOKEN_ENDPOINT_AUTH_UNSPECIFIED, fmt.Errorf("tokenEndpointAuthMethod %s requires a clientSecret", agentgateway.OIDCTokenEndpointAuthMethodClientSecretBasic)
		}
		return api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC, nil
	case agentgateway.OIDCTokenEndpointAuthMethodClientSecretPost:
		if !hasClientSecret {
			return api.TrafficPolicySpec_OIDC_TOKEN_ENDPOINT_AUTH_UNSPECIFIED, fmt.Errorf("tokenEndpointAuthMethod %s requires a clientSecret", agentgateway.OIDCTokenEndpointAuthMethodClientSecretPost)
		}
		return api.TrafficPolicySpec_OIDC_CLIENT_SECRET_POST, nil
	case agentgateway.OIDCTokenEndpointAuthMethodNone:
		if hasClientSecret {
			return api.TrafficPolicySpec_OIDC_TOKEN_ENDPOINT_AUTH_UNSPECIFIED, fmt.Errorf("tokenEndpointAuthMethod %s must not be paired with a clientSecret", agentgateway.OIDCTokenEndpointAuthMethodNone)
		}
		return api.TrafficPolicySpec_OIDC_NONE, nil
	default:
		return api.TrafficPolicySpec_OIDC_TOKEN_ENDPOINT_AUTH_UNSPECIFIED, fmt.Errorf("unsupported tokenEndpointAuthMethod %q", *oidcCfg.TokenEndpointAuthMethod)
	}
}
