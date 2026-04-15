package plugins

import "k8s.io/apimachinery/pkg/types"

// GatewayTrafficOIDC marks a gateway that has compiled traffic OIDC policy.
type GatewayTrafficOIDC struct {
	Gateway types.NamespacedName
}

func (g GatewayTrafficOIDC) ResourceName() string {
	return g.Gateway.String()
}

func (g GatewayTrafficOIDC) Equals(other GatewayTrafficOIDC) bool {
	return g.Gateway == other.Gateway
}
