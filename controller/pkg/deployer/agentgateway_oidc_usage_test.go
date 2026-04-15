package deployer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/test"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	agwplugins "github.com/agentgateway/agentgateway/controller/pkg/agentgateway/plugins"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

func TestBuildOIDCRequiredGatewaysCollectionIncludesCompiledTrafficOIDC(t *testing.T) {
	stop := test.NewStop(t)
	gateway := testGateway()

	collection := buildOIDCRequiredGatewaysCollection(
		newOIDCTestInputs(
			stop,
			[]*gwv1.GatewayClass{testGatewayClass()},
			[]*gwv1.Gateway{gateway},
			[]agwplugins.GatewayTrafficOIDC{{Gateway: types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}}},
		),
		krt.NewStaticCollection[*agentgateway.AgentgatewayParameters](nil, nil, krt.WithStop(stop)),
	)

	require.True(t, collection.WaitUntilSynced(stop))
	assert.NotNil(t, collection.GetKey(types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}.String()))
}

func TestBuildOIDCRequiredGatewaysCollectionIncludesLocalRawConfigOIDC(t *testing.T) {
	stop := test.NewStop(t)
	gateway := testGateway()
	gateway.Spec.Infrastructure = &gwv1.GatewayInfrastructure{
		ParametersRef: &gwv1.LocalParametersReference{
			Group: gwv1.Group(agentgateway.GroupName),
			Kind:  gwv1.Kind(wellknown.AgentgatewayParametersGVK.Kind),
			Name:  "local-oidc",
		},
	}
	agwp := &agentgateway.AgentgatewayParameters{
		ObjectMeta: metav1.ObjectMeta{Name: "local-oidc", Namespace: gateway.Namespace},
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
	}
	agwParams := krt.NewStaticCollection[*agentgateway.AgentgatewayParameters](nil, []*agentgateway.AgentgatewayParameters{agwp}, krt.WithStop(stop))

	collection := buildOIDCRequiredGatewaysCollection(
		newOIDCTestInputs(
			stop,
			[]*gwv1.GatewayClass{testGatewayClass()},
			[]*gwv1.Gateway{gateway},
			nil,
		),
		agwParams,
	)

	require.True(t, collection.WaitUntilSynced(stop))
	assert.NotNil(t, collection.GetKey(types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}.String()))
}

func TestBuildOIDCRequiredGatewaysCollectionSkipsGatewaysWithoutOIDC(t *testing.T) {
	stop := test.NewStop(t)
	gateway := testGateway()

	collection := buildOIDCRequiredGatewaysCollection(
		newOIDCTestInputs(
			stop,
			[]*gwv1.GatewayClass{testGatewayClass()},
			[]*gwv1.Gateway{gateway},
			nil,
		),
		krt.NewStaticCollection[*agentgateway.AgentgatewayParameters](nil, nil, krt.WithStop(stop)),
	)

	require.True(t, collection.WaitUntilSynced(stop))
	assert.Nil(t, collection.GetKey(types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}.String()))
}

func TestRawConfigUsesLocalOIDCNarrowly(t *testing.T) {
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

func newOIDCTestInputs(
	stop <-chan struct{},
	gatewayClasses []*gwv1.GatewayClass,
	gateways []*gwv1.Gateway,
	trafficOIDCGateways []agwplugins.GatewayTrafficOIDC,
) *Inputs {
	return &Inputs{
		AgwCollections: &agwplugins.AgwCollections{
			GatewayClasses: krt.NewStaticCollection[*gwv1.GatewayClass](nil, gatewayClasses, krt.WithStop(stop)),
			Gateways:       krt.NewStaticCollection[*gwv1.Gateway](nil, gateways, krt.WithStop(stop)),
		},
		TrafficOIDCGateways:        krt.NewStaticCollection[agwplugins.GatewayTrafficOIDC](nil, trafficOIDCGateways, krt.WithStop(stop)),
		AgentgatewayControllerName: wellknown.DefaultAgwControllerName,
	}
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
