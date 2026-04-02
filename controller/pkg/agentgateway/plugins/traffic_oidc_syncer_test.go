package plugins_test

import (
	"testing"
	"time"

	"istio.io/istio/pkg/ptr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	api "github.com/agentgateway/agentgateway/api"
	agwv1alpha1 "github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/shared"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/plugins"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/testutils"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

const testDummyIDPRootCA = `-----BEGIN CERTIFICATE-----
MIIFfDCCA2SgAwIBAgIUOBEwNkgGCBk5gTlks4MgZjBwcB0wDQYJKoZIhvcNAQEL
BQAwKzEpMCcGA1UEAwwgZHVtbXktaWRwLmRlZmF1bHQsTz1rZ2F0ZXdheS5kZXYw
HhcNMjUxMjEyMjIyNTAyWhcNMzUxMjEwMjIyNTAyWjArMSkwJwYDVQQDDCBkdW1t
eS1pZHAuZGVmYXVsdCxPPWtnYXRld2F5LmRldjCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBAKPDXO2JEDlruWLQACZqQyFoJTw9dUpay+QcVrgnDv8ULM9F
wSVpIgiT7/reqfWQsyWH8bhyZ60SD2v6BqRdvU8d5G7Lzjjiv7D1kRmdoM05rHeW
rFWrMsd3tTVYIdkDwsOqb/4/3YXhzZstI8N9I9mqQFfR0Oahjwub1fQqGkU4AldO
WGTgsllI0ZDV8IDuARlOQ8ZysxL2axxXJ4Io4eDMZ6uwbeW5JXv/ajLz3Gx9vpWf
LlfPHCB4/Z+EErw/g55PEM8ftvK5ijT2+QPULSdrkO/YjByV9IPNjYou9JEcI1KP
Q2q4VcjQV83dcRFDw11o6MhOicVNwdTFBia6aStpxU/fsYaoaPiK0OWOZ3SjtoNV
PT17geh5kX+4eTmzdC/9hFh+qncyzfHdomBFQlamQ5Pzg3ngLoNm5Iyk/OuUgLg8
sgYf7coYDygzzagxxpTRS7VyfwqLlMaRbqBUrX9IHVpn17CqtsrI1ihadv9q4wc3
Mxt2rdT1GfpE7yCB/NrAzCe2ZVWkNkX8Zb0taD79r/daOBgakHf9L/EqYTsgGO3s
XiF7G3lbRpLwOKHiHP9YbQCdoh8Y3qzGi9DLlmDIaQShtJPUmCb7u7kL9bW2SPRL
+zH2ZY5258CZWndAGe06wQVgLv0aI7kre+Sf1YfZxRbzE595TBWQO/RRT3I7AgMB
AAGjgZcwgZQwHQYDVR0OBBYEFAIkfyn6riDFT/LhatXG1uS5u8HKMB8GA1UdIwQY
MBaAFAIkfyn6riDFT/LhatXG1uS5u8HKMA8GA1UdEwEB/wQFMAMBAf8wQQYDVR0R
BDowOIIRZHVtbXktaWRwLmRlZmF1bHSCI2R1bW15LWlkcC5kZWZhdWx0LnN2Yy5j
bHVzdGVyLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4ICAQAxzxHhT9uvTBHKeu+7zOdU
A+rju5gPjeItds3r2YdHqqjidkK53qWnvrqteoguT8lxGXaSL0QzL3l9eFp80BIP
8MmlI+zs8Q/cO9gCeEf+3ul+nx2YzF33W/PNahHfLDbLIFDoQMkhTyemEh1GEqmm
6frHgO2OgdIO6jyIF0GN0SFvCW6J32k3teRsN2OLRQCuCftJ/Q2dwuXZfmx0sf0R
Hz7JNBdH9U8iCYhSefd3VWCro2sPB3XT7evH9+orFikvbb5fggo4WGjvc7CPKlMj
59PGlloJCUP9FIhR5/oot6yH9NsdOzDWY51makMhE4nq/ET8omaawSCclTE8mDWk
+s/8MBQkk6T72zaVX6Eqnb0RatIHkr9C6zfy/ZE4E5A6Lw+EwdGPaXg5pCBO0miM
jImoFyNvXEGWY3w6AX8ho1L27ZiTApMTc2fYUYCy4QP+MDjEp1+yFrjFSFpUhF0Z
+Tl37cUWZcm4nUxEcu/pfedKyliR2yKBfi3jg7cDzVB86tSHzIvPgxpl2ivEEb0E
ohncCC1Z//SKb7QFs1Obry3hIIBpEyVVvGB580AdxgLY9nhrvv/6gw01JtEPXczV
1BTCWIUc6WafBlAiWrm3tR36kaRn2RrIlCAFrMznQMafCfMLCTWsYudkrabl7W9n
yamda6yFfH9bkPO+XBK3lQ==
-----END CERTIFICATE-----`

func TestOIDCDiscoveryBackendProducesGatewayBackendResource(t *testing.T) {
	authn := &agwv1alpha1.OIDCAuthentication{
		Issuer: "https://issuer.example.com",
		Discovery: &agwv1alpha1.OIDCDiscovery{
			BackendRef: &gwv1.BackendObjectReference{
				Group: ptr.Of(gwv1.Group(wellknown.AgentgatewayBackendGVK.Group)),
				Kind:  ptr.Of(gwv1.Kind(wellknown.AgentgatewayBackendGVK.Kind)),
				Name:  gwv1.ObjectName("dummy-idp"),
				Port:  ptr.Of(gwv1.PortNumber(8443)),
			},
		},
		ClientID:        "client-id",
		ClientSecretRef: corev1.LocalObjectReference{Name: "oidc-client"},
		RedirectURI:     "https://app.example.com/oauth/callback",
		Scopes:          []string{"profile", "email"},
	}
	policy := &agwv1alpha1.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-policy", Namespace: "default"},
		Spec: agwv1alpha1.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(wellknown.GatewayGVK.Group),
					Kind:  gwv1.Kind(wellknown.GatewayGVK.Kind),
					Name:  gwv1.ObjectName("gateway"),
				},
			}},
			Traffic: &agwv1alpha1.Traffic{
				Phase:              ptr.Of(agwv1alpha1.PolicyPhasePreRouting),
				OIDCAuthentication: authn,
			},
		},
	}
	backend := &agwv1alpha1.AgentgatewayBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "dummy-idp", Namespace: "default"},
		Spec: agwv1alpha1.AgentgatewayBackendSpec{
			Static: &agwv1alpha1.StaticBackend{
				Host: "dummy-idp.default",
				Port: 8443,
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-client", Namespace: "default"},
		Data: map[string][]byte{
			wellknown.ClientSecret: []byte("super-secret"),
		},
	}

	ctx := testutils.BuildMockPolicyContext(t, []any{
		testGatewayClass(),
		testGateway(),
		policy,
		secret,
		backend,
	})
	providerConfigMap := testOIDCProviderConfigMap(t, ctx, authn, policy.Namespace, policy.Name)
	ctx = testutils.BuildMockPolicyContext(t, []any{
		testGatewayClass(),
		testGateway(),
		policy,
		secret,
		backend,
		providerConfigMap,
	})

	_, syncer := testutils.Syncer(t, ctx, "AgentgatewayPolicy", "AgentgatewayBackend")

	var backendResources []*api.Backend
	for _, resource := range syncer.Outputs.Resources.List() {
		if resource.Gateway != (types.NamespacedName{Namespace: "default", Name: "gateway"}) {
			continue
		}
		if backendResource := resource.Resource.GetBackend(); backendResource != nil {
			backendResources = append(backendResources, backendResource)
		}
	}

	if len(backendResources) != 1 {
		t.Fatalf("expected 1 backend resource for gateway-targeted oidc backend, got %d", len(backendResources))
	}
	if backendResources[0].Key != "default/dummy-idp" {
		t.Fatalf("unexpected backend key %q", backendResources[0].Key)
	}
}

func TestOIDCDiscoveryBackendPreservesInlineTLSPolicy(t *testing.T) {
	authn := &agwv1alpha1.OIDCAuthentication{
		Issuer: "https://issuer.example.com",
		Discovery: &agwv1alpha1.OIDCDiscovery{
			BackendRef: &gwv1.BackendObjectReference{
				Group: ptr.Of(gwv1.Group(wellknown.AgentgatewayBackendGVK.Group)),
				Kind:  ptr.Of(gwv1.Kind(wellknown.AgentgatewayBackendGVK.Kind)),
				Name:  gwv1.ObjectName("dummy-idp"),
				Port:  ptr.Of(gwv1.PortNumber(8443)),
			},
		},
		ClientID:        "client-id",
		ClientSecretRef: corev1.LocalObjectReference{Name: "oidc-client"},
		RedirectURI:     "https://app.example.com/oauth/callback",
	}
	policy := &agwv1alpha1.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-policy", Namespace: "default"},
		Spec: agwv1alpha1.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(wellknown.GatewayGVK.Group),
					Kind:  gwv1.Kind(wellknown.GatewayGVK.Kind),
					Name:  gwv1.ObjectName("gateway"),
				},
			}},
			Traffic: &agwv1alpha1.Traffic{
				Phase:              ptr.Of(agwv1alpha1.PolicyPhasePreRouting),
				OIDCAuthentication: authn,
			},
		},
	}
	backend := &agwv1alpha1.AgentgatewayBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "dummy-idp", Namespace: "default"},
		Spec: agwv1alpha1.AgentgatewayBackendSpec{
			Policies: &agwv1alpha1.BackendFull{
				BackendSimple: agwv1alpha1.BackendSimple{
					TLS: &agwv1alpha1.BackendTLS{
						Sni:               ptr.Of("dummy-idp.default"),
						CACertificateRefs: []corev1.LocalObjectReference{{Name: "ca"}},
					},
				},
			},
			Static: &agwv1alpha1.StaticBackend{
				Host: "dummy-idp.default",
				Port: 8443,
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-client", Namespace: "default"},
		Data: map[string][]byte{
			wellknown.ClientSecret: []byte("super-secret"),
		},
	}
	ca := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "default"},
		Data: map[string]string{
			"ca.crt": testDummyIDPRootCA,
		},
	}

	ctx := testutils.BuildMockPolicyContext(t, []any{
		testGatewayClass(),
		testGateway(),
		policy,
		secret,
		backend,
		ca,
	})
	providerConfigMap := testOIDCProviderConfigMap(t, ctx, authn, policy.Namespace, policy.Name)
	ctx = testutils.BuildMockPolicyContext(t, []any{
		testGatewayClass(),
		testGateway(),
		policy,
		secret,
		backend,
		ca,
		providerConfigMap,
	})

	_, syncer := testutils.Syncer(t, ctx, "AgentgatewayPolicy", "AgentgatewayBackend")

	for _, resource := range syncer.Outputs.Resources.List() {
		if resource.Gateway != (types.NamespacedName{Namespace: "default", Name: "gateway"}) {
			continue
		}
		backendResource := resource.Resource.GetBackend()
		if backendResource == nil || backendResource.Key != "default/dummy-idp" {
			continue
		}
		if len(backendResource.InlinePolicies) != 1 {
			t.Fatalf("expected one inline backend policy, got %d", len(backendResource.InlinePolicies))
		}
		backendTLS := backendResource.InlinePolicies[0].GetBackendTls()
		if backendTLS == nil {
			t.Fatal("expected backend tls inline policy to be preserved")
		}
		if len(backendTLS.Root) == 0 {
			t.Fatal("expected backend tls inline policy to include root CA data")
		}
		return
	}

	t.Fatal("expected to find dummy-idp backend resource for gateway")
}

func testOIDCProviderConfigMap(
	t *testing.T,
	ctx plugins.PolicyCtx,
	authn *agwv1alpha1.OIDCAuthentication,
	namespace, name string,
) *corev1.ConfigMap {
	t.Helper()

	source, err := oidc.BuildProviderSource(
		ctx.Krt,
		ctx.Resolver,
		types.NamespacedName{Namespace: namespace, Name: name},
		"",
		authn,
	)
	if err != nil {
		t.Fatalf("BuildProviderSource() error = %v", err)
	}

	cmName := oidc.ProviderConfigMapNamespacedName("agentgateway-system", oidc.DefaultProviderStorePrefix, source.RequestKey)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName.Name,
			Namespace: cmName.Namespace,
		},
	}
	err = oidc.SetProviderConfigInConfigMap(cm, oidc.ProviderConfig{
		RequestKey:            source.RequestKey,
		DiscoveryURL:          source.Target.URL,
		FetchedAt:             time.Unix(1711972800, 0).UTC(),
		Issuer:                string(authn.Issuer),
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		TokenEndpoint:         "https://issuer.example.com/token",
		TokenEndpointAuth:     "clientSecretBasic",
		JwksURI:               "https://issuer.example.com/jwks",
		JwksInline:            `{"keys":[]}`,
	})
	if err != nil {
		t.Fatalf("SetProviderConfigInConfigMap() error = %v", err)
	}
	return cm
}

func testGatewayClass() *gwv1.GatewayClass {
	return &gwv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "agentgateway"},
		Spec: gwv1.GatewayClassSpec{
			ControllerName: gwv1.GatewayController(wellknown.DefaultAgwControllerName),
		},
	}
}

func testGateway() *gwv1.Gateway {
	return &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default"},
		Spec: gwv1.GatewaySpec{
			GatewayClassName: "agentgateway",
			Listeners: []gwv1.Listener{{
				Name:     "http",
				Protocol: gwv1.HTTPProtocolType,
				Port:     8080,
			}},
		},
	}
}
