package plugins

import (
	"testing"

	"github.com/stretchr/testify/require"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/jwks"
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
