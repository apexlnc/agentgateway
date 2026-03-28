package oidc

import (
	"fmt"
	"reflect"
	"time"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
)

type OwnerKind string

const (
	OwnerKindPolicy OwnerKind = "AgentgatewayPolicy"
)

type ProviderOwnerID struct {
	Kind      OwnerKind
	Namespace string
	Name      string
	Path      string
}

func (o ProviderOwnerID) String() string {
	return fmt.Sprintf("%s/%s/%s#%s", o.Kind, o.Namespace, o.Name, o.Path)
}

type OwnerKey = ProviderOwnerID

type ProviderOwner struct {
	ID               ProviderOwnerID
	DefaultNamespace string
	Issuer           string
	Discovery        agentgateway.OIDCDiscovery
	TTL              time.Duration
}

func (o ProviderOwner) ResourceName() string {
	return o.ID.String()
}

func (o ProviderOwner) Equals(other ProviderOwner) bool {
	return o.ID == other.ID &&
		o.DefaultNamespace == other.DefaultNamespace &&
		o.Issuer == other.Issuer &&
		o.TTL == other.TTL &&
		reflect.DeepEqual(o.Discovery, other.Discovery)
}

func OwnersFromPolicy(policy *agentgateway.AgentgatewayPolicy) []ProviderOwner {
	if len(policy.Spec.TargetRefs) == 0 || policy.Spec.Traffic == nil || policy.Spec.Traffic.JWTAuthentication == nil {
		return nil
	}

	var owners []ProviderOwner
	for providerIdx, provider := range policy.Spec.Traffic.JWTAuthentication.Providers {
		if provider.JWKS.Discovery == nil {
			continue
		}
		owners = append(owners, PolicyJWTProviderLookupOwner(policy.Namespace, policy.Name, providerIdx, string(provider.Issuer), *provider.JWKS.Discovery))
	}

	return owners
}

func PolicyJWTProviderLookupOwner(namespace, name string, providerIndex int, issuer string, discovery agentgateway.OIDCDiscovery) ProviderOwner {
	return ProviderOwner{
		ID: ProviderOwnerID{
			Kind:      OwnerKindPolicy,
			Namespace: namespace,
			Name:      name,
			Path:      fmt.Sprintf("spec.traffic.jwtAuthentication.providers[%d].jwks.discovery", providerIndex),
		},
		DefaultNamespace: namespace,
		Issuer:           issuer,
		Discovery:        discovery,
		TTL:              ttlForDiscovery(discovery),
	}
}

func ttlForDiscovery(discovery agentgateway.OIDCDiscovery) time.Duration {
	if discovery.CacheDuration == nil {
		return 5 * time.Minute
	}
	return discovery.CacheDuration.Duration
}
