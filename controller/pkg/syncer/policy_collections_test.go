package syncer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/test"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/api"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/plugins"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

func TestGatewayTrafficOIDCCollection(t *testing.T) {
	stop := test.NewStop(t)
	gateway := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"}}
	key := types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}

	gateways := krt.NewStaticCollection[*gwv1.Gateway](nil, []*gwv1.Gateway{gateway}, krt.WithStop(stop))
	policies := krt.NewStaticCollection[plugins.AgwPolicy](nil, []plugins.AgwPolicy{
		{
			Gateway: &key,
			Policy: &api.Policy{
				Key: "oidc",
				Kind: &api.Policy_Traffic{
					Traffic: &api.TrafficPolicySpec{
						Kind: &api.TrafficPolicySpec_Oidc{
							Oidc: &api.TrafficPolicySpec_OIDC{Issuer: "https://issuer.example.com"},
						},
					},
				},
			},
		},
		{
			Gateway: &key,
			Policy: &api.Policy{
				Key:  "no-oidc",
				Kind: &api.Policy_Traffic{Traffic: &api.TrafficPolicySpec{}},
			},
		},
	}, krt.WithStop(stop))

	collection := GatewayTrafficOIDCCollection(gateways, policies, krtutil.KrtOptions{})
	require.True(t, collection.WaitUntilSynced(stop))
	assert.Equal(t, &plugins.GatewayTrafficOIDC{Gateway: key}, collection.GetKey(key.String()))
}
