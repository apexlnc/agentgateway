package plugins

import (
	"errors"
	"testing"

	"istio.io/istio/pkg/kube/krt"
	"k8s.io/apimachinery/pkg/types"

	"github.com/agentgateway/agentgateway/api"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	oidcpkg "github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
)

// stubOIDCLookup is a test-only fake for oidcpkg.Lookup.
type stubOIDCLookup struct {
	provider *oidcpkg.DiscoveredProvider
	err      error
}

func (s stubOIDCLookup) ResolveForOwner(krt.HandlerContext, oidcpkg.RemoteOidcOwner) (*oidcpkg.DiscoveredProvider, error) {
	return s.provider, s.err
}

func makeOIDC() *agentgateway.OIDC {
	return &agentgateway.OIDC{
		IssuerURL:   "https://idp.example.com",
		ClientID:    "my-client",
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"openid", "email"},
	}
}

func makeDiscoveredProvider() *oidcpkg.DiscoveredProvider {
	return &oidcpkg.DiscoveredProvider{
		IssuerURL:             "https://idp.example.com",
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
		JwksJSON:              `{"keys":[]}`,
	}
}

func TestProcessOIDCPolicyHappyPath(t *testing.T) {
	oidcCfg := makeOIDC()
	provider := makeDiscoveredProvider()
	policyKey := types.NamespacedName{Namespace: "default", Name: "my-policy"}

	result, err := processOIDCPolicy(
		PolicyCtx{Krt: krt.TestingDummyContext{}},
		oidcCfg,
		"traffic/default/my-policy",
		policyKey,
		stubOIDCLookup{provider: provider},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil policy")
	}

	oidcSpec := result.GetTraffic().GetOidc()
	if oidcSpec == nil {
		t.Fatal("expected oidc spec in policy")
	}
	if oidcSpec.Issuer != provider.IssuerURL {
		t.Errorf("issuer: got %q, want %q", oidcSpec.Issuer, provider.IssuerURL)
	}
	if oidcSpec.AuthorizationEndpoint != provider.AuthorizationEndpoint {
		t.Errorf("authorization_endpoint: got %q, want %q", oidcSpec.AuthorizationEndpoint, provider.AuthorizationEndpoint)
	}
	if oidcSpec.TokenEndpoint != provider.TokenEndpoint {
		t.Errorf("token_endpoint: got %q, want %q", oidcSpec.TokenEndpoint, provider.TokenEndpoint)
	}
	if oidcSpec.JwksInline != provider.JwksJSON {
		t.Errorf("jwks_inline: got %q, want %q", oidcSpec.JwksInline, provider.JwksJSON)
	}
	if oidcSpec.ClientId != oidcCfg.ClientID {
		t.Errorf("client_id: got %q, want %q", oidcSpec.ClientId, oidcCfg.ClientID)
	}
	if oidcSpec.RedirectUri != oidcCfg.RedirectURI {
		t.Errorf("redirect_uri: got %q, want %q", oidcSpec.RedirectUri, oidcCfg.RedirectURI)
	}
	if len(oidcSpec.Scopes) != 2 || oidcSpec.Scopes[0] != "openid" || oidcSpec.Scopes[1] != "email" {
		t.Errorf("scopes: got %v, want [openid email]", oidcSpec.Scopes)
	}
	if oidcSpec.TokenEndpointAuth != api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC {
		t.Errorf("token_endpoint_auth: got %v, want %v", oidcSpec.TokenEndpointAuth, api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC)
	}
	// client_secret must remain empty (delivered out-of-band in Phase 6)
	if oidcSpec.ClientSecret != "" {
		t.Errorf("client_secret must be empty, got %q", oidcSpec.ClientSecret)
	}
}

func TestProcessOIDCPolicyPolicyIDForAgentgatewayPolicy(t *testing.T) {
	policyKey := types.NamespacedName{Namespace: "prod", Name: "auth-policy"}

	result, err := processOIDCPolicy(
		PolicyCtx{Krt: krt.TestingDummyContext{}},
		makeOIDC(),
		"traffic/prod/auth-policy",
		policyKey,
		stubOIDCLookup{provider: makeDiscoveredProvider()},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "policy/prod/auth-policy"
	got := result.GetTraffic().GetOidc().GetPolicyId()
	if got != want {
		t.Errorf("policy_id: got %q, want %q", got, want)
	}
}

func TestProcessOIDCPolicyKeyUsesOIDCSuffix(t *testing.T) {
	policyKey := types.NamespacedName{Namespace: "default", Name: "my-policy"}

	result, err := processOIDCPolicy(
		PolicyCtx{Krt: krt.TestingDummyContext{}},
		makeOIDC(),
		"traffic/default/my-policy",
		policyKey,
		stubOIDCLookup{provider: makeDiscoveredProvider()},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantKey := "traffic/default/my-policy" + oidcPolicySuffix
	if result.Key != wantKey {
		t.Errorf("policy key: got %q, want %q", result.Key, wantKey)
	}
}

func TestProcessOIDCPolicyTokenEndpointAuthUsesDiscoveryValue(t *testing.T) {
	oidcCfg := makeOIDC()
	provider := makeDiscoveredProvider()
	provider.TokenEndpointAuthMethodsSupported = []string{"client_secret_post"}

	result, err := processOIDCPolicy(
		PolicyCtx{Krt: krt.TestingDummyContext{}},
		oidcCfg,
		"traffic/default/my-policy",
		types.NamespacedName{Namespace: "default", Name: "my-policy"},
		stubOIDCLookup{provider: provider},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := result.GetTraffic().GetOidc().GetTokenEndpointAuth(); got != api.TrafficPolicySpec_OIDC_CLIENT_SECRET_POST {
		t.Errorf("token_endpoint_auth: got %v, want %v", got, api.TrafficPolicySpec_OIDC_CLIENT_SECRET_POST)
	}
}

func TestProcessOIDCPolicyTokenEndpointAuthOverrideWins(t *testing.T) {
	oidcCfg := makeOIDC()
	override := "ClientSecretBasic"
	oidcCfg.TokenEndpointAuthMethod = &override
	provider := makeDiscoveredProvider()
	provider.TokenEndpointAuthMethodsSupported = []string{"client_secret_post"}

	result, err := processOIDCPolicy(
		PolicyCtx{Krt: krt.TestingDummyContext{}},
		oidcCfg,
		"traffic/default/my-policy",
		types.NamespacedName{Namespace: "default", Name: "my-policy"},
		stubOIDCLookup{provider: provider},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := result.GetTraffic().GetOidc().GetTokenEndpointAuth(); got != api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC {
		t.Errorf("token_endpoint_auth: got %v, want %v", got, api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC)
	}
}

func TestProcessOIDCPolicyLookupNotYetFetchedReturnsError(t *testing.T) {
	sentinel := errors.New("oidc provider not yet fetched")

	result, err := processOIDCPolicy(
		PolicyCtx{Krt: krt.TestingDummyContext{}},
		makeOIDC(),
		"traffic/default/my-policy",
		types.NamespacedName{Namespace: "default", Name: "my-policy"},
		stubOIDCLookup{err: sentinel},
	)

	if err == nil {
		t.Fatal("expected error when lookup returns error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
	// Policy must still be returned (possibly with empty OIDC data)
	if result == nil {
		t.Fatal("expected non-nil policy even on lookup error")
	}
}

func TestProcessOIDCPolicyLookupReturnsNilProviderReturnsError(t *testing.T) {
	result, err := processOIDCPolicy(
		PolicyCtx{Krt: krt.TestingDummyContext{}},
		makeOIDC(),
		"traffic/default/my-policy",
		types.NamespacedName{Namespace: "default", Name: "my-policy"},
		stubOIDCLookup{provider: nil, err: nil},
	)

	if err == nil {
		t.Fatal("expected error when lookup returns nil provider")
	}
	if result == nil {
		t.Fatal("expected non-nil policy even on nil provider")
	}
}

func TestProcessOIDCPolicyNilLookupReturnsError(t *testing.T) {
	_, err := processOIDCPolicy(
		PolicyCtx{Krt: krt.TestingDummyContext{}},
		makeOIDC(),
		"traffic/default/my-policy",
		types.NamespacedName{Namespace: "default", Name: "my-policy"},
		nil,
	)

	if err == nil {
		t.Fatal("expected error when oidc lookup is nil")
	}
}

func TestProcessOIDCPolicyResultHasTrafficKind(t *testing.T) {
	result, err := processOIDCPolicy(
		PolicyCtx{Krt: krt.TestingDummyContext{}},
		makeOIDC(),
		"traffic/default/my-policy",
		types.NamespacedName{Namespace: "default", Name: "my-policy"},
		stubOIDCLookup{provider: makeDiscoveredProvider()},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// GetTraffic() returns nil if the kind is not Traffic.
	if result.GetTraffic() == nil {
		t.Error("expected Traffic kind on policy, got nil")
	}
	// GetOidc() must be populated.
	if result.GetTraffic().GetOidc() == nil {
		t.Error("expected oidc spec inside Traffic policy")
	}
}
