package oidc

import (
	"time"

	"k8s.io/apimachinery/pkg/api/equality"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
)

// OidcRefreshInterval is how often the controller re-fetches OIDC discovery
// documents and JWKS. Fixed (not user-tunable); IdP JWKS rotation overlap
// windows are days, so an hour is conservative across the board.
const OidcRefreshInterval = time.Hour

// RemoteOidcOwner identifies the Kubernetes owner (AgentgatewayPolicy) that
// triggered the OIDC discovery fetch and carries the configuration needed to
// resolve and perform the fetch.
type RemoteOidcOwner struct {
	ID               remotecache.OwnerID
	DefaultNamespace string
	Config           agentgateway.OIDC
	TTL              time.Duration
}

func (o RemoteOidcOwner) ResourceName() string {
	return o.ID.String()
}

func (o RemoteOidcOwner) Equals(other RemoteOidcOwner) bool {
	return o.ID == other.ID &&
		o.DefaultNamespace == other.DefaultNamespace &&
		o.TTL == other.TTL &&
		equality.Semantic.DeepEqual(o.Config, other.Config)
}

// OwnerFromPolicy extracts the RemoteOidcOwner from an AgentgatewayPolicy that
// has a .spec.traffic.oidc field set. The CRD permits at most one OIDC config
// per policy, so the result is at most one owner.
func OwnerFromPolicy(policy *agentgateway.AgentgatewayPolicy) (RemoteOidcOwner, bool) {
	if len(policy.Spec.TargetRefs) == 0 && len(policy.Spec.TargetSelectors) == 0 {
		return RemoteOidcOwner{}, false
	}

	if policy.Spec.Traffic == nil {
		return RemoteOidcOwner{}, false
	}

	return PolicyOIDCLookupOwner(policy.Namespace, policy.Name, policy.Spec.Traffic.OIDC)
}

func PolicyOIDCLookupOwner(namespace, name string, oidcCfg *agentgateway.OIDC) (RemoteOidcOwner, bool) {
	if oidcCfg == nil {
		return RemoteOidcOwner{}, false
	}

	return RemoteOidcOwner{
		ID: remotecache.OwnerID{
			Kind:      remotecache.OwnerKindPolicy,
			Namespace: namespace,
			Name:      name,
			Path:      "spec.traffic.oidc",
		},
		DefaultNamespace: namespace,
		Config:           *oidcCfg,
		TTL:              OidcRefreshInterval,
	}, true
}
