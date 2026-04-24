package oidc

import (
	"time"

	"k8s.io/apimachinery/pkg/api/equality"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotecache"
)

// OidcRefreshInterval is how often the controller re-fetches OIDC discovery
// documents and JWKS from the IdP. Fixed (not user-tunable) to keep the
// dataplane behavior uniform: every mainstream IdP rotates JWKS with overlap
// windows of days or longer, so an hour is conservative across the board, and
// exposing a per-policy knob would let operators silently degrade JWT
// validation by lengthening the interval past their IdP's overlap window.
const OidcRefreshInterval = time.Hour

// RemoteOidcOwner identifies the Kubernetes owner (AgentgatewayPolicy) that
// triggered the OIDC discovery fetch and carries the configuration needed to
// resolve and perform the fetch.
type RemoteOidcOwner struct {
	ID               OidcOwnerID
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

// OwnersFromPolicy extracts RemoteOidcOwner values from an AgentgatewayPolicy
// that has a .spec.traffic.oidc field set.
func OwnersFromPolicy(policy *agentgateway.AgentgatewayPolicy) []RemoteOidcOwner {
	if len(policy.Spec.TargetRefs) == 0 && len(policy.Spec.TargetSelectors) == 0 {
		return nil
	}

	if policy.Spec.Traffic == nil {
		return nil
	}

	owner, ok := PolicyOIDCLookupOwner(policy.Namespace, policy.Name, policy.Spec.Traffic.OIDC)
	if !ok {
		return nil
	}

	return []RemoteOidcOwner{
		owner,
	}
}

func PolicyOIDCLookupOwner(namespace, name string, oidcCfg *agentgateway.OIDC) (RemoteOidcOwner, bool) {
	if oidcCfg == nil {
		return RemoteOidcOwner{}, false
	}

	return RemoteOidcOwner{
		ID: OidcOwnerID{
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
