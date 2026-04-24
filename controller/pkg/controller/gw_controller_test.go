package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

func TestGatewayRefsFromPolicyStatusUsesGatewayAncestorsForOurController(t *testing.T) {
	policy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc",
			Namespace: "policy-ns",
		},
		Status: gwv1.PolicyStatus{
			Ancestors: []gwv1.PolicyAncestorStatus{
				{
					AncestorRef: gwv1.ParentReference{
						Group:     ptrTo(gwv1.Group(wellknown.GatewayGVK.Group)),
						Kind:      ptrTo(gwv1.Kind(wellknown.GatewayGVK.Kind)),
						Name:      gwv1.ObjectName("gw"),
						Namespace: ptrTo(gwv1.Namespace("gateway-ns")),
					},
					ControllerName: gwv1.GatewayController(wellknown.DefaultAgwControllerName),
				},
				{
					AncestorRef: gwv1.ParentReference{
						Group: ptrTo(gwv1.Group(wellknown.GatewayGVK.Group)),
						Kind:  ptrTo(gwv1.Kind(wellknown.GatewayGVK.Kind)),
						Name:  gwv1.ObjectName("other"),
					},
					ControllerName: gwv1.GatewayController("other.dev/controller"),
				},
			},
		},
	}

	got := gatewayRefsFromPolicyStatus(policy, wellknown.DefaultAgwControllerName)

	assert.Equal(t, sets.New(types.NamespacedName{Namespace: "gateway-ns", Name: "gw"}), got)
}

func TestGatewayRefsFromPolicyStatusDefaultsNamespaceFromPolicy(t *testing.T) {
	policy := &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc",
			Namespace: "policy-ns",
		},
		Status: gwv1.PolicyStatus{
			Ancestors: []gwv1.PolicyAncestorStatus{{
				AncestorRef: gwv1.ParentReference{
					Group: ptrTo(gwv1.Group(wellknown.GatewayGVK.Group)),
					Kind:  ptrTo(gwv1.Kind(wellknown.GatewayGVK.Kind)),
					Name:  gwv1.ObjectName("gw"),
				},
				ControllerName: gwv1.GatewayController(wellknown.DefaultAgwControllerName),
			}},
		},
	}

	got := gatewayRefsFromPolicyStatus(policy, wellknown.DefaultAgwControllerName)

	assert.Equal(t, sets.New(types.NamespacedName{Namespace: "policy-ns", Name: "gw"}), got)
}

func ptrTo[T any](v T) *T {
	return &v
}
