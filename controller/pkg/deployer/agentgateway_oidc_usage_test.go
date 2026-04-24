package deployer

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/kube/krt"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/shared"
	agwplugins "github.com/agentgateway/agentgateway/controller/pkg/agentgateway/plugins"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

type alwaysSynced struct{}

func (alwaysSynced) WaitUntilSynced(stop <-chan struct{}) bool {
	return true
}

func (alwaysSynced) HasSynced() bool {
	return true
}

func TestRawConfigOIDCCollection_ResolvedParametersRequireOIDCUnmarshalsOncePerReconcile(t *testing.T) {
	var detections atomic.Int32
	col := &rawConfigOIDCCollection{
		detectRawConfigUsesLocalOIDC: func(raw *apiextensionsv1.JSON) bool {
			detections.Add(1)
			return rawConfigUsesLocalOIDC(raw)
		},
	}

	rawConfig := []byte(`{
		"binds": [{
			"port": 8080,
			"listeners": [{
				"policies": {
					"oidc": {
						"issuer": "https://issuer.example.com"
					}
				}
			}]
		}]
	}`)

	resolvedForValues := &resolvedParameters{
		gatewayAGWP: &agentgateway.AgentgatewayParameters{
			Spec: agentgateway.AgentgatewayParametersSpec{
				AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
					RawConfig: &apiextensionsv1.JSON{Raw: append([]byte(nil), rawConfig...)},
				},
			},
		},
	}
	resolvedForPostProcess := &resolvedParameters{
		gatewayAGWP: &agentgateway.AgentgatewayParameters{
			Spec: agentgateway.AgentgatewayParametersSpec{
				AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
					RawConfig: &apiextensionsv1.JSON{Raw: append([]byte(nil), rawConfig...)},
				},
			},
		},
	}

	assert.True(t, col.resolvedParametersRequireOIDC(resolvedForValues))
	assert.True(t, col.resolvedParametersRequireOIDC(resolvedForPostProcess))
	assert.Equal(t, int32(1), detections.Load())
}

func TestRawConfigUsesLocalOIDC_BindListenerPolicy(t *testing.T) {
	t.Parallel()

	assert.True(t, rawConfigUsesLocalOIDC(&apiextensionsv1.JSON{Raw: []byte(`{
		"binds": [{
			"port": 8080,
			"listeners": [{
				"policies": {
					"oidc": {
						"issuer": "https://issuer.example.com"
					}
				}
			}]
		}]
	}`)}))
}

func TestRawConfigUsesLocalOIDC_TopLevelPolicies(t *testing.T) {
	t.Parallel()

	assert.True(t, rawConfigUsesLocalOIDC(&apiextensionsv1.JSON{Raw: []byte(`{
		"policies": [{
			"policy": {
				"oidc": {
					"issuer": "https://issuer.example.com"
				}
			}
		}]
	}`)}))
}

func TestRawConfigUsesLocalOIDC_RoutePolicy(t *testing.T) {
	t.Parallel()

	assert.True(t, rawConfigUsesLocalOIDC(&apiextensionsv1.JSON{Raw: []byte(`{
		"binds": [{
			"port": 8080,
			"listeners": [{
				"routes": [{
					"policies": {
						"oidc": {
							"issuer": "https://issuer.example.com"
						}
					}
				}]
			}]
		}]
	}`)}))
}

func TestRawConfigUsesLocalOIDCNarrowly(t *testing.T) {
	t.Parallel()

	// A key named "oidc" nested under an arbitrary metadata key is not OIDC usage.
	assert.False(t, rawConfigUsesLocalOIDC(&apiextensionsv1.JSON{Raw: []byte(`{
		"config": {
			"metadata": {
				"oidc": {
					"note": "not a local policy surface"
				}
			}
		}
	}`)}))
}

func TestRawConfigUsesLocalOIDC_NilOrEmpty(t *testing.T) {
	t.Parallel()

	assert.False(t, rawConfigUsesLocalOIDC(nil))
	assert.False(t, rawConfigUsesLocalOIDC(&apiextensionsv1.JSON{}))
}

func TestRawConfigOIDCCollection_ResolvedParametersRequireOIDC(t *testing.T) {
	t.Parallel()

	col := &rawConfigOIDCCollection{}

	resolved := &resolvedParameters{
		gatewayAGWP: &agentgateway.AgentgatewayParameters{
			Spec: agentgateway.AgentgatewayParametersSpec{
				AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
					RawConfig: &apiextensionsv1.JSON{Raw: []byte(`{
						"binds": [{"port": 8080, "listeners": [{"policies": {"oidc": {"issuer": "https://x.example.com"}}}]}]
					}`)},
				},
			},
		},
	}

	assert.True(t, col.resolvedParametersRequireOIDC(resolved))
	assert.False(t, col.resolvedParametersRequireOIDC(nil))
	assert.False(t, col.resolvedParametersRequireOIDC(&resolvedParameters{}))
}

func TestRawConfigOIDCCollection_GatewayRequiresOIDCForGatewayPolicy(t *testing.T) {
	t.Parallel()

	gw := &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
	}
	policy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-oidc", Namespace: "default"},
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(wellknown.GatewayGVK.Group),
					Kind:  gwv1.Kind(wellknown.GatewayGVK.Kind),
					Name:  gwv1.ObjectName("gw"),
				},
			}},
			Traffic: &agentgateway.Traffic{
				OIDC: &agentgateway.OIDC{
					IssuerURL:   "https://issuer.example",
					ClientID:    "client",
					RedirectURI: "https://app.example/callback",
				},
			},
		},
		Status: gwv1.PolicyStatus{
			Ancestors: []gwv1.PolicyAncestorStatus{{
				AncestorRef: gwv1.ParentReference{
					Group:     ptrTo(gwv1.Group(wellknown.GatewayGVK.Group)),
					Kind:      ptrTo(gwv1.Kind(wellknown.GatewayGVK.Kind)),
					Name:      gwv1.ObjectName("gw"),
					Namespace: ptrTo(gwv1.Namespace("default")),
				},
				ControllerName: gwv1.GatewayController("agentgateway.dev/agentgateway"),
			}},
		},
	}

	col := &rawConfigOIDCCollection{
		agwCollections: &agwplugins.AgwCollections{
			AgentgatewayPolicies: krt.NewStaticCollection(alwaysSynced{}, []*agentgateway.AgentgatewayPolicy{policy}),
			ControllerName:       "agentgateway.dev/agentgateway",
		},
	}

	assert.True(t, col.gatewayRequiresOIDC(gw, nil))
}

func TestRawConfigOIDCCollection_GatewayRequiresOIDCDefaultsAncestorNamespaceFromPolicy(t *testing.T) {
	t.Parallel()

	gw := &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
	}
	policy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-oidc", Namespace: "default"},
		Spec: agentgateway.AgentgatewayPolicySpec{
			Traffic: &agentgateway.Traffic{
				OIDC: &agentgateway.OIDC{
					IssuerURL:   "https://issuer.example",
					ClientID:    "client",
					RedirectURI: "https://app.example/callback",
				},
			},
		},
		Status: gwv1.PolicyStatus{
			Ancestors: []gwv1.PolicyAncestorStatus{{
				AncestorRef: gwv1.ParentReference{
					Group: ptrTo(gwv1.Group(wellknown.GatewayGVK.Group)),
					Kind:  ptrTo(gwv1.Kind(wellknown.GatewayGVK.Kind)),
					Name:  gwv1.ObjectName("gw"),
				},
				ControllerName: gwv1.GatewayController("agentgateway.dev/agentgateway"),
			}},
		},
	}

	col := &rawConfigOIDCCollection{
		agwCollections: &agwplugins.AgwCollections{
			AgentgatewayPolicies: krt.NewStaticCollection(alwaysSynced{}, []*agentgateway.AgentgatewayPolicy{policy}),
			ControllerName:       "agentgateway.dev/agentgateway",
		},
	}

	assert.True(t, col.gatewayRequiresOIDC(gw, nil))
}

func TestRawConfigOIDCCollection_GatewayRequiresOIDCForDelegatedRoutePolicyViaStatusAncestor(t *testing.T) {
	t.Parallel()

	gw := &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
	}
	policy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "route-oidc", Namespace: "team1"},
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(wellknown.HTTPRouteGVK.Group),
					Kind:  gwv1.Kind(wellknown.HTTPRouteGVK.Kind),
					Name:  gwv1.ObjectName("child-team1-foo"),
				},
			}},
			Traffic: &agentgateway.Traffic{
				OIDC: &agentgateway.OIDC{
					IssuerURL:   "https://issuer.example",
					ClientID:    "client",
					RedirectURI: "https://app.example/callback",
				},
			},
		},
		Status: gwv1.PolicyStatus{
			Ancestors: []gwv1.PolicyAncestorStatus{{
				AncestorRef: gwv1.ParentReference{
					Group:     ptrTo(gwv1.Group(wellknown.GatewayGVK.Group)),
					Kind:      ptrTo(gwv1.Kind(wellknown.GatewayGVK.Kind)),
					Name:      gwv1.ObjectName("gw"),
					Namespace: ptrTo(gwv1.Namespace("default")),
				},
				ControllerName: gwv1.GatewayController("agentgateway.dev/agentgateway"),
			}},
		},
	}

	col := &rawConfigOIDCCollection{
		agwCollections: &agwplugins.AgwCollections{
			AgentgatewayPolicies: krt.NewStaticCollection(alwaysSynced{}, []*agentgateway.AgentgatewayPolicy{policy}),
			ControllerName:       "agentgateway.dev/agentgateway",
		},
	}

	assert.True(t, col.gatewayRequiresOIDC(gw, nil))
}

func TestRawConfigOIDCCollection_GatewayRequiresOIDCIgnoresAncestorsFromOtherControllers(t *testing.T) {
	t.Parallel()

	gw := &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
	}
	policy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-oidc", Namespace: "default"},
		Spec: agentgateway.AgentgatewayPolicySpec{
			Traffic: &agentgateway.Traffic{
				OIDC: &agentgateway.OIDC{
					IssuerURL:   "https://issuer.example",
					ClientID:    "client",
					RedirectURI: "https://app.example/callback",
				},
			},
		},
		Status: gwv1.PolicyStatus{
			Ancestors: []gwv1.PolicyAncestorStatus{{
				AncestorRef: gwv1.ParentReference{
					Group:     ptrTo(gwv1.Group(wellknown.GatewayGVK.Group)),
					Kind:      ptrTo(gwv1.Kind(wellknown.GatewayGVK.Kind)),
					Name:      gwv1.ObjectName("gw"),
					Namespace: ptrTo(gwv1.Namespace("default")),
				},
				ControllerName: gwv1.GatewayController("other.dev/controller"),
			}},
		},
	}

	col := &rawConfigOIDCCollection{
		agwCollections: &agwplugins.AgwCollections{
			AgentgatewayPolicies: krt.NewStaticCollection(alwaysSynced{}, []*agentgateway.AgentgatewayPolicy{policy}),
			ControllerName:       "agentgateway.dev/agentgateway",
		},
	}

	assert.False(t, col.gatewayRequiresOIDC(gw, nil))
}

func ptrTo[T any](v T) *T {
	return &v
}
