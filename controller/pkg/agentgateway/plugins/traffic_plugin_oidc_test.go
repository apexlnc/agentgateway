package plugins

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/api"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/shared"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/jwks"
	agwutils "github.com/agentgateway/agentgateway/controller/pkg/agentgateway/utils"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

func TestProcessJWTAuthenticationPolicyUsesInlineJWKSForDiscoverySource(t *testing.T) {
	var inlineOwner jwks.RemoteJwksOwner

	ctx := PolicyCtx{
		Krt: krt.TestingDummyContext{},
		References: ReferenceIndex{
			explicitReferences: ReferenceTypes{
				InlineJWKS: func(krtctx krt.HandlerContext, owner jwks.RemoteJwksOwner) (string, error) {
					inlineOwner = owner
					return `{"keys":[]}`, nil
				},
			},
		},
	}

	jwt := &agentgateway.JWTAuthentication{
		Mode: agentgateway.JWTAuthenticationModeStrict,
		Providers: []agentgateway.JWTProvider{{
			Issuer: "https://issuer.example/realms/team",
			JWKS: agentgateway.JWKS{
				Discovery: &agentgateway.OIDCDiscovery{
					BackendRef: gwv1.BackendObjectReference{
						Group:     ptr.Of(gwv1.Group("")),
						Kind:      ptr.Of(gwv1.Kind("Service")),
						Name:      gwv1.ObjectName("dummy-idp"),
						Namespace: ptr.Of(gwv1.Namespace("default")),
						Port:      ptr.Of(gwv1.PortNumber(8080)),
					},
				},
			},
		}},
	}

	policy, err := processJWTAuthenticationPolicy(ctx, jwt, nil, "traffic/default/policy", types.NamespacedName{Namespace: "default", Name: "policy"})
	require.NoError(t, err)
	require.Equal(t, "spec.traffic.jwtAuthentication.providers[0].jwks.discovery", inlineOwner.ID.Path)
	require.NotNil(t, inlineOwner.Discovery)
	require.Nil(t, inlineOwner.Remote)
	require.Equal(t, "https://issuer.example/realms/team", inlineOwner.Issuer)

	translated := policy.GetTraffic().GetJwt()
	require.Len(t, translated.Providers, 1)
	require.Equal(t, `{"keys":[]}`, translated.Providers[0].GetInline())
}

func TestTranslateAgentgatewayPolicySurfacesDiscoveryLookupFailureInStatus(t *testing.T) {
	policy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "policy",
		},
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(wellknown.GatewayGVK.Group),
					Kind:  gwv1.Kind(wellknown.GatewayGVK.Kind),
					Name:  gwv1.ObjectName("gateway"),
				},
			}},
			Traffic: &agentgateway.Traffic{
				JWTAuthentication: &agentgateway.JWTAuthentication{
					Mode: agentgateway.JWTAuthenticationModeStrict,
					Providers: []agentgateway.JWTProvider{{
						Issuer: "https://issuer.example/realms/team",
						JWKS: agentgateway.JWKS{
							Discovery: &agentgateway.OIDCDiscovery{
								BackendRef: gwv1.BackendObjectReference{
									Group:     ptr.Of(gwv1.Group("")),
									Kind:      ptr.Of(gwv1.Kind("Service")),
									Name:      gwv1.ObjectName("dummy-idp"),
									Namespace: ptr.Of(gwv1.Namespace("default")),
									Port:      ptr.Of(gwv1.PortNumber(8080)),
								},
							},
						},
					}},
				},
			},
		},
	}

	status, policies := TranslateAgentgatewayPolicy(krt.TestingDummyContext{}, policy, &AgwCollections{
		ControllerName: "agentgateway.dev/test-controller",
	}, ReferenceIndex{
		explicitReferences: ReferenceTypes{
			PolicyTargets: func(krtctx krt.HandlerContext, namespace string, name gwv1.ObjectName, gk schema.GroupKind, sectionName *gwv1.SectionName) (*api.PolicyTarget, bool) {
				if gk != wellknown.GatewayGVK.GroupKind() {
					return nil, false
				}
				return &api.PolicyTarget{Kind: agwutils.GatewayTarget(namespace, string(name), sectionName)}, true
			},
			InlineJWKS: func(krtctx krt.HandlerContext, owner jwks.RemoteJwksOwner) (string, error) {
				return "", fmt.Errorf(`jwks keyset for "https://issuer.example/jwks" isn't available (not yet fetched or fetch failed)`)
			},
		},
	})

	require.Len(t, policies, 1)
	require.Len(t, status.Ancestors, 1)

	accepted := meta.FindStatusCondition(status.Ancestors[0].Conditions, string(shared.PolicyConditionAccepted))
	require.NotNil(t, accepted)
	assert.Equal(t, metav1.ConditionTrue, accepted.Status)
	assert.Equal(t, string(shared.PolicyReasonPartiallyValid), accepted.Reason)
	assert.Contains(t, accepted.Message, `jwks keyset for "https://issuer.example/jwks" isn't available`)
}
