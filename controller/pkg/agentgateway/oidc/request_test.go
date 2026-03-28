package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

func TestResolveDiscoveryEndpoint(t *testing.T) {
	serviceDiscovery := discoveryProvider(gwv1.BackendObjectReference{
		Group:     ptr.Of(gwv1.Group("")),
		Kind:      ptr.Of(gwv1.Kind("Service")),
		Name:      gwv1.ObjectName("dummy-idp"),
		Namespace: ptr.Of(gwv1.Namespace("default")),
		Port:      ptr.Of(gwv1.PortNumber(8080)),
	})
	backendDiscovery := discoveryProvider(gwv1.BackendObjectReference{
		Group: ptr.Of(gwv1.Group(wellknown.AgentgatewayBackendGVK.Group)),
		Kind:  ptr.Of(gwv1.Kind(wellknown.AgentgatewayBackendGVK.Kind)),
		Name:  gwv1.ObjectName("dummy-idp"),
		Port:  ptr.Of(gwv1.PortNumber(8080)),
	})

	tests := []struct {
		name                string
		inputs              []any
		discovery           *agentgateway.OIDCDiscovery
		issuer              string
		disableAutoResolver bool
		expectedURL         string
		expectedError       string
	}{
		{
			name:                "errors when resolver is not initialized",
			discovery:           serviceDiscovery,
			issuer:              "https://issuer.example/realms/team",
			disableAutoResolver: true,
			expectedError:       "remote http resolver hasn't been initialized",
		},
		{
			name:          "errors when discovery transport is not initialized",
			issuer:        "https://issuer.example/realms/team",
			expectedError: "oidc discovery transport hasn't been initialized",
		},
		{
			name:        "service-backed oidc discovery uses issuer path",
			discovery:   serviceDiscovery,
			issuer:      "https://issuer.example/realms/team",
			expectedURL: "http://dummy-idp.default.svc.cluster.local:8080/realms/team/.well-known/openid-configuration",
		},
		{
			name: "backend-backed oidc discovery uses issuer path",
			inputs: []any{
				staticBackend("dummy-idp", "dummy-idp.default", 8080),
			},
			discovery:   backendDiscovery,
			issuer:      "https://issuer.example/realms/team",
			expectedURL: "http://dummy-idp.default:8080/realms/team/.well-known/openid-configuration",
		},
		{
			name:          "returns resolver error for missing backend",
			discovery:     backendDiscovery,
			issuer:        "https://issuer.example/realms/team",
			expectedError: "backend default/dummy-idp not found, policy default/gw-policy",
		},
		{
			name:          "rejects invalid issuer urls",
			discovery:     serviceDiscovery,
			issuer:        "not-a-url",
			expectedError: `issuer "not-a-url" must be an absolute URL`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var endpointResolver remotehttp.Resolver = newResolver(tt.inputs)
			if tt.disableAutoResolver {
				endpointResolver = nil
			}

			endpoint, err := oidc.ResolveDiscoveryEndpoint(krt.TestingDummyContext{}, endpointResolver, "gw-policy", "default", tt.issuer, tt.discovery)
			if tt.expectedError != "" {
				require.EqualError(t, err, tt.expectedError)
				require.Nil(t, endpoint)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, endpoint)
			require.Equal(t, tt.expectedURL, endpoint.Target.URL)
			require.Equal(t, endpoint.Key, endpoint.Target.Key())
		})
	}
}

func TestDiscoveryPathForIssuer(t *testing.T) {
	tests := []struct {
		issuer       string
		expectedPath string
	}{
		{
			issuer:       "https://issuer.example",
			expectedPath: "/.well-known/openid-configuration",
		},
		{
			issuer:       "https://issuer.example/realms/team",
			expectedPath: "/realms/team/.well-known/openid-configuration",
		},
		{
			issuer:       "https://issuer.example/realms/team/",
			expectedPath: "/realms/team/.well-known/openid-configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			path, err := oidc.DiscoveryPathForIssuer(tt.issuer)
			require.NoError(t, err)
			require.Equal(t, tt.expectedPath, path)
		})
	}
}

func TestDiscoveredJWKSTarget(t *testing.T) {
	target, err := oidc.DiscoveredJWKSTarget("https://issuer.example/realms/team", oidc.ProviderConfig{
		Issuer:  "https://issuer.example/realms/team",
		JwksURI: "https://www.googleapis.com/oauth2/v3/certs",
	})
	require.NoError(t, err)
	require.Equal(t, "https://www.googleapis.com/oauth2/v3/certs", target.URL)
}

func discoveryProvider(backendRef gwv1.BackendObjectReference) *agentgateway.OIDCDiscovery {
	return &agentgateway.OIDCDiscovery{
		BackendRef: backendRef,
	}
}

func staticBackend(name, host string, port int32) *agentgateway.AgentgatewayBackend {
	return &agentgateway.AgentgatewayBackend{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: agentgateway.AgentgatewayBackendSpec{
			Static: &agentgateway.StaticBackend{
				Host: host,
				Port: port,
			},
		},
	}
}

func newResolver(inputs []any) remotehttp.Resolver {
	var (
		services           []*corev1.Service
		backends           []*agentgateway.AgentgatewayBackend
		policies           []*agentgateway.AgentgatewayPolicy
		backendTLSPolicies []*gwv1.BackendTLSPolicy
	)

	for _, input := range inputs {
		switch typed := input.(type) {
		case *corev1.Service:
			services = append(services, typed)
		case *agentgateway.AgentgatewayBackend:
			backends = append(backends, typed)
		case *agentgateway.AgentgatewayPolicy:
			policies = append(policies, typed)
		case *gwv1.BackendTLSPolicy:
			backendTLSPolicies = append(backendTLSPolicies, typed)
		}
	}

	return remotehttp.NewResolver(remotehttp.Inputs{
		ConfigMaps:           krt.NewStaticCollection[*corev1.ConfigMap](alwaysSynced{}, nil),
		Services:             krt.NewStaticCollection[*corev1.Service](alwaysSynced{}, services),
		Backends:             krt.NewStaticCollection[*agentgateway.AgentgatewayBackend](alwaysSynced{}, backends),
		AgentgatewayPolicies: krt.NewStaticCollection[*agentgateway.AgentgatewayPolicy](alwaysSynced{}, policies),
		BackendTLSPolicies:   krt.NewStaticCollection[*gwv1.BackendTLSPolicy](alwaysSynced{}, backendTLSPolicies),
	})
}

type alwaysSynced struct{}

func (alwaysSynced) WaitUntilSynced(stop <-chan struct{}) bool {
	return true
}

func (alwaysSynced) HasSynced() bool {
	return true
}
