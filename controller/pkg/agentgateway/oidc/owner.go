package oidc

import (
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
)

// OidcOwnerID identifies the Kubernetes resource that owns an OIDC discovery request.
type OidcOwnerID struct {
	Namespace string
	Name      string
	// Path is the spec path of the OIDC field within the owning resource.
	Path string
}

func (o OidcOwnerID) String() string {
	return fmt.Sprintf("AgentgatewayPolicy/%s/%s#%s", o.Namespace, o.Name, o.Path)
}

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
		oidcConfigEqual(o.Config, other.Config)
}

func oidcConfigEqual(a, b agentgateway.OIDC) bool {
	return a.IssuerURL == b.IssuerURL &&
		a.ClientID == b.ClientID &&
		localObjectReferenceEqual(a.ClientSecret, b.ClientSecret) &&
		a.RedirectURI == b.RedirectURI &&
		slices.Equal(a.Scopes, b.Scopes) &&
		backendObjectReferenceEqual(a.Backend, b.Backend) &&
		durationEqual(a.RefreshInterval, b.RefreshInterval) &&
		stringPointerEqual(a.TokenEndpointAuthMethod, b.TokenEndpointAuthMethod)
}

func localObjectReferenceEqual(a, b *corev1.LocalObjectReference) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	default:
		return *a == *b
	}
}

func backendObjectReferenceEqual(a, b *gwv1.BackendObjectReference) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	default:
		return stringPointerEqual(a.Group, b.Group) &&
			stringPointerEqual(a.Kind, b.Kind) &&
			a.Name == b.Name &&
			stringPointerEqual(a.Namespace, b.Namespace) &&
			portNumberPointerEqual(a.Port, b.Port)
	}
}

func durationEqual(a, b *metav1.Duration) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	default:
		return a.Duration == b.Duration
	}
}

func stringPointerEqual[T ~string](a, b *T) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	default:
		return *a == *b
	}
}

func portNumberPointerEqual(a, b *gwv1.PortNumber) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	default:
		return *a == *b
	}
}

// OwnersFromPolicy extracts RemoteOidcOwner values from an AgentgatewayPolicy
// that has a .spec.traffic.oidc field set.
func OwnersFromPolicy(policy *agentgateway.AgentgatewayPolicy) []RemoteOidcOwner {
	if len(policy.Spec.TargetRefs) == 0 {
		return nil
	}

	if policy.Spec.Traffic == nil || policy.Spec.Traffic.OIDC == nil {
		return nil
	}

	oidcCfg := *policy.Spec.Traffic.OIDC
	return []RemoteOidcOwner{
		{
			ID: OidcOwnerID{
				Namespace: policy.Namespace,
				Name:      policy.Name,
				Path:      "spec.traffic.oidc",
			},
			DefaultNamespace: policy.Namespace,
			Config:           oidcCfg,
			TTL:              TTLForOIDC(oidcCfg),
		},
	}
}

// TTLForOIDC returns the configured refresh interval for an OIDC provider,
// defaulting to 1 hour if not set.
func TTLForOIDC(cfg agentgateway.OIDC) time.Duration {
	if cfg.RefreshInterval == nil {
		return time.Hour
	}
	return cfg.RefreshInterval.Duration
}
