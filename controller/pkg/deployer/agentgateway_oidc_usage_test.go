package deployer

import (
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
)

func TestRawConfigOIDCCollection_ResolvedParametersRequireOIDCUnmarshalsOncePerReconcile(t *testing.T) {
	originalUnmarshal := unmarshalLocalConfigOIDCDetector
	t.Cleanup(func() {
		unmarshalLocalConfigOIDCDetector = originalUnmarshal
	})

	var unmarshals atomic.Int32
	unmarshalLocalConfigOIDCDetector = func(data []byte, v any) error {
		unmarshals.Add(1)
		return json.Unmarshal(data, v)
	}

	col := &rawConfigOIDCCollection{
		detectRawConfigUsesLocalOIDC: rawConfigUsesLocalOIDC,
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
	assert.Equal(t, int32(1), unmarshals.Load())
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

func TestResolvedParametersUseLocalOIDC_GatewayAGWPRawConfig(t *testing.T) {
	t.Parallel()

	resolved := &resolvedParameters{
		gatewayAGWP: &agentgateway.AgentgatewayParameters{
			ObjectMeta: metav1.ObjectMeta{Name: "local-oidc", Namespace: "default"},
			Spec: agentgateway.AgentgatewayParametersSpec{
				AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
					RawConfig: &apiextensionsv1.JSON{Raw: []byte(`{
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
					}`)},
				},
			},
		},
	}

	assert.True(t, resolvedParametersUseLocalOIDC(resolved))
}

func TestResolvedParametersUseLocalOIDC_GatewayClassAGWPRawConfig(t *testing.T) {
	t.Parallel()

	resolved := &resolvedParameters{
		gatewayClassAGWP: &agentgateway.AgentgatewayParameters{
			ObjectMeta: metav1.ObjectMeta{Name: "gwc-oidc", Namespace: "agentgateway-system"},
			Spec: agentgateway.AgentgatewayParametersSpec{
				AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
					RawConfig: &apiextensionsv1.JSON{Raw: []byte(`{
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
					}`)},
				},
			},
		},
	}

	assert.True(t, resolvedParametersUseLocalOIDC(resolved))
}

func TestResolvedParametersUseLocalOIDC_NoOIDC(t *testing.T) {
	t.Parallel()

	resolved := &resolvedParameters{
		gatewayAGWP: &agentgateway.AgentgatewayParameters{
			Spec: agentgateway.AgentgatewayParametersSpec{
				AgentgatewayParametersConfigs: agentgateway.AgentgatewayParametersConfigs{
					RawConfig: &apiextensionsv1.JSON{Raw: []byte(`{
						"binds": [{
							"port": 8080,
							"listeners": [{
								"policies": {
									"jwtAuthentication": {}
								}
							}]
						}]
					}`)},
				},
			},
		},
	}

	assert.False(t, resolvedParametersUseLocalOIDC(resolved))
}

func TestResolvedParametersUseLocalOIDC_Nil(t *testing.T) {
	t.Parallel()

	assert.False(t, resolvedParametersUseLocalOIDC(nil))
	assert.False(t, resolvedParametersUseLocalOIDC(&resolvedParameters{}))
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
