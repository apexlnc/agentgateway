package plugins

import (
	"strings"
	"testing"
	"time"

	"istio.io/client-go/pkg/apis/networking/v1"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	"istio.io/istio/pkg/ptr"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	inf "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gwv1b1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	api "github.com/agentgateway/agentgateway/api"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/shared"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

func TestProcessOIDCAuthenticationPolicy(t *testing.T) {
	authn := &agentgateway.OIDCAuthentication{
		Issuer: "https://issuer.example.com",
		Discovery: &agentgateway.OIDCDiscovery{
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
	policy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-policy", Namespace: "default"},
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(wellknown.GatewayGVK.Group),
					Kind:  gwv1.Kind(wellknown.GatewayGVK.Kind),
					Name:  gwv1.ObjectName("test"),
				},
			}},
			Traffic: &agentgateway.Traffic{
				Phase:              ptr.Of(agentgateway.PolicyPhasePreRouting),
				OIDCAuthentication: authn,
			},
		},
	}

	backend := &agentgateway.AgentgatewayBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "dummy-idp", Namespace: "default"},
		Spec: agentgateway.AgentgatewayBackendSpec{
			Static: &agentgateway.StaticBackend{
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
	ctx := buildMockOIDCPolicyContext(t, []any{
		testGatewayClass(),
		testGateway(),
		policy,
		secret,
		backend,
	})
	providerConfigMap := testOIDCProviderConfigMap(t, ctx, authn, policy.Namespace, policy.Name)
	ctx = buildMockOIDCPolicyContext(t, []any{
		testGatewayClass(),
		testGateway(),
		policy,
		secret,
		backend,
		providerConfigMap,
	})

	got, err := processOIDCAuthenticationPolicy(
		ctx,
		policy,
		authn,
		policy.Spec.Traffic.Phase,
		"traffic/default/oidc-policy",
		types.NamespacedName{Namespace: "default", Name: "oidc-policy"},
	)
	if err != nil {
		t.Fatalf("processOIDCAuthenticationPolicy() error = %v", err)
	}

	traffic := got.GetTraffic()
	if traffic == nil {
		t.Fatalf("expected traffic policy, got nil")
	}
	oidcPolicy := traffic.GetOidc()
	if oidcPolicy == nil {
		t.Fatalf("expected oidc traffic policy, got nil")
	}
	if got.Key != "traffic/default/oidc-policy:oidc" {
		t.Fatalf("unexpected policy key %q", got.Key)
	}
	if oidcPolicy.PolicyId != "policy/traffic/default/oidc-policy:oidc" {
		t.Fatalf("unexpected policy_id %q", oidcPolicy.PolicyId)
	}
	if oidcPolicy.ClientSecret != "super-secret" {
		t.Fatalf("unexpected client secret %q", oidcPolicy.ClientSecret)
	}
	if oidcPolicy.TokenEndpointAuth != api.TrafficPolicySpec_OIDC_CLIENT_SECRET_BASIC {
		t.Fatalf("unexpected token endpoint auth %v", oidcPolicy.TokenEndpointAuth)
	}
	if oidcPolicy.ProviderBackend == nil || oidcPolicy.ProviderBackend.GetBackend() == "" {
		t.Fatalf("expected provider backend to be set, got %#v", oidcPolicy.ProviderBackend)
	}
	if traffic.Phase != api.TrafficPolicySpec_GATEWAY {
		t.Fatalf("unexpected phase %v", traffic.Phase)
	}
}

func TestProcessOIDCAuthenticationPolicyPreservesClientSecretWhitespace(t *testing.T) {
	authn := &agentgateway.OIDCAuthentication{
		Issuer: "https://issuer.example.com",
		Discovery: &agentgateway.OIDCDiscovery{
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
	policy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-policy", Namespace: "default"},
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(wellknown.GatewayGVK.Group),
					Kind:  gwv1.Kind(wellknown.GatewayGVK.Kind),
					Name:  gwv1.ObjectName("test"),
				},
			}},
			Traffic: &agentgateway.Traffic{
				Phase:              ptr.Of(agentgateway.PolicyPhasePreRouting),
				OIDCAuthentication: authn,
			},
		},
	}
	backend := &agentgateway.AgentgatewayBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "dummy-idp", Namespace: "default"},
		Spec: agentgateway.AgentgatewayBackendSpec{
			Static: &agentgateway.StaticBackend{
				Host: "dummy-idp.default",
				Port: 8443,
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-client", Namespace: "default"},
		Data: map[string][]byte{
			wellknown.ClientSecret: []byte("  super-secret  "),
		},
	}
	ctx := buildMockOIDCPolicyContext(t, []any{
		testGatewayClass(),
		testGateway(),
		policy,
		secret,
		backend,
	})
	providerConfigMap := testOIDCProviderConfigMap(t, ctx, authn, policy.Namespace, policy.Name)
	ctx = buildMockOIDCPolicyContext(t, []any{
		testGatewayClass(),
		testGateway(),
		policy,
		secret,
		backend,
		providerConfigMap,
	})

	got, err := processOIDCAuthenticationPolicy(
		ctx,
		policy,
		authn,
		policy.Spec.Traffic.Phase,
		"traffic/default/oidc-policy",
		types.NamespacedName{Namespace: "default", Name: "oidc-policy"},
	)
	if err != nil {
		t.Fatalf("processOIDCAuthenticationPolicy() error = %v", err)
	}

	oidcPolicy := got.GetTraffic().GetOidc()
	if oidcPolicy == nil {
		t.Fatal("expected oidc traffic policy, got nil")
	}
	if oidcPolicy.ClientSecret != "  super-secret  " {
		t.Fatalf("unexpected client secret %q", oidcPolicy.ClientSecret)
	}
}

func TestBackendReferencesFromPolicyIncludesOIDCDiscoveryBackend(t *testing.T) {
	policy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "route-policy", Namespace: "default"},
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(wellknown.HTTPRouteGVK.Group),
					Kind:  gwv1.Kind(wellknown.HTTPRouteGVK.Kind),
					Name:  gwv1.ObjectName("route"),
				},
			}},
			Traffic: &agentgateway.Traffic{
				OIDCAuthentication: &agentgateway.OIDCAuthentication{
					Issuer: "https://issuer.example.com",
					Discovery: &agentgateway.OIDCDiscovery{
						BackendRef: &gwv1.BackendObjectReference{
							Group: ptr.Of(gwv1.Group(wellknown.AgentgatewayBackendGVK.Group)),
							Kind:  ptr.Of(gwv1.Kind(wellknown.AgentgatewayBackendGVK.Kind)),
							Name:  gwv1.ObjectName("dummy-idp"),
							Port:  ptr.Of(gwv1.PortNumber(8443)),
						},
					},
				},
			},
		},
	}

	attachments := BackendReferencesFromPolicy(policy)
	if len(attachments) != 1 {
		t.Fatalf("expected 1 backend attachment, got %d", len(attachments))
	}

	got := attachments[0]
	if got.Target.Kind != wellknown.HTTPRouteGVK.Kind || got.Target.Namespace != "default" || got.Target.Name != "route" {
		t.Fatalf("unexpected target attachment: %#v", got.Target)
	}
	if got.Backend.Kind != wellknown.AgentgatewayBackendGVK.Kind || got.Backend.Namespace != "default" || got.Backend.Name != "dummy-idp" {
		t.Fatalf("unexpected backend attachment: %#v", got.Backend)
	}
}

func TestValidateOIDCListenerModesRejectsMixedGatewayAndRoutePhase(t *testing.T) {
	gatewayPhasePolicy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-oidc", Namespace: "default"},
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(wellknown.GatewayGVK.Group),
					Kind:  gwv1.Kind(wellknown.GatewayGVK.Kind),
					Name:  gwv1.ObjectName("test"),
				},
			}},
			Traffic: &agentgateway.Traffic{
				Phase:              ptr.Of(agentgateway.PolicyPhasePreRouting),
				OIDCAuthentication: &agentgateway.OIDCAuthentication{Issuer: "https://issuer.example.com"},
			},
		},
	}
	routePhasePolicy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "route-oidc", Namespace: "default"},
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(wellknown.GatewayGVK.Group),
					Kind:  gwv1.Kind(wellknown.GatewayGVK.Kind),
					Name:  gwv1.ObjectName("test"),
				},
			}},
			Traffic: &agentgateway.Traffic{
				OIDCAuthentication: &agentgateway.OIDCAuthentication{Issuer: "https://issuer.example.com"},
			},
		},
	}

	ctx := buildMockOIDCPolicyContext(t, []any{
		testGatewayClass(),
		testGateway(),
		gatewayPhasePolicy,
		routePhasePolicy,
	})

	err := validateOIDCListenerModes(ctx, gatewayPhasePolicy)
	if err == nil {
		t.Fatal("expected mixed gateway/route oidc validation error")
	}
	if got := err.Error(); got == "" || !containsAll(got, "cannot mix gateway-phase oidc with route-phase oidc", "default/test/http") {
		t.Fatalf("unexpected error %q", got)
	}
}

func testOIDCProviderConfigMap(
	t *testing.T,
	ctx PolicyCtx,
	authn *agentgateway.OIDCAuthentication,
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
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
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

func containsAll(value string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}

func buildMockOIDCPolicyContext(t *testing.T, inputs []any) PolicyCtx {
	t.Helper()

	mock := krttest.NewMock(t, inputs)
	col := &AgwCollections{
		Namespaces:           krttest.GetMockCollection[*corev1.Namespace](mock),
		Nodes:                krttest.GetMockCollection[*corev1.Node](mock),
		Pods:                 krttest.GetMockCollection[*corev1.Pod](mock),
		Services:             krttest.GetMockCollection[*corev1.Service](mock),
		Secrets:              krttest.GetMockCollection[*corev1.Secret](mock),
		ConfigMaps:           krttest.GetMockCollection[*corev1.ConfigMap](mock),
		EndpointSlices:       krttest.GetMockCollection[*discovery.EndpointSlice](mock),
		WorkloadEntries:      krttest.GetMockCollection[*v1.WorkloadEntry](mock),
		ServiceEntries:       krttest.GetMockCollection[*v1.ServiceEntry](mock),
		GatewayClasses:       krttest.GetMockCollection[*gwv1.GatewayClass](mock),
		Gateways:             krttest.GetMockCollection[*gwv1.Gateway](mock),
		HTTPRoutes:           krttest.GetMockCollection[*gwv1.HTTPRoute](mock),
		GRPCRoutes:           krttest.GetMockCollection[*gwv1.GRPCRoute](mock),
		TCPRoutes:            krttest.GetMockCollection[*gwv1a2.TCPRoute](mock),
		TLSRoutes:            krttest.GetMockCollection[*gwv1.TLSRoute](mock),
		ReferenceGrants:      krttest.GetMockCollection[*gwv1b1.ReferenceGrant](mock),
		BackendTLSPolicies:   krttest.GetMockCollection[*gwv1.BackendTLSPolicy](mock),
		ListenerSets:         krttest.GetMockCollection[*gwv1.ListenerSet](mock),
		InferencePools:       krttest.GetMockCollection[*inf.InferencePool](mock),
		Backends:             krttest.GetMockCollection[*agentgateway.AgentgatewayBackend](mock),
		AgentgatewayPolicies: krttest.GetMockCollection[*agentgateway.AgentgatewayPolicy](mock),
		ControllerName:       wellknown.DefaultAgwControllerName,
		SystemNamespace:      "agentgateway-system",
		IstioNamespace:       "istio-system",
		ClusterID:            "Kubernetes",
	}
	col.SetupIndexes()
	references := BuildReferenceIndex(
		nil,
		nil,
		DefaultReferenceTypes(col),
	)
	return PolicyCtx{
		Krt:         krt.TestingDummyContext{},
		Collections: col,
		References:  references,
		Resolver:    remotehttp.NewResolver(col.ConfigMaps, col.Backends, col.AgentgatewayPolicies),
	}
}
