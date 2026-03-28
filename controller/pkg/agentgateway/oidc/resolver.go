package oidc

import (
	"time"

	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type ResolvedProviderRequest struct {
	OwnerID ProviderOwnerID
	Issuer  string
	Target  remotehttp.ResolvedTarget
	TTL     time.Duration
}

type Resolver interface {
	ResolveOwner(krtctx krt.HandlerContext, owner ProviderOwner) (*ResolvedProviderRequest, error)
}

type defaultResolver struct {
	endpointResolver remotehttp.Resolver
}

func NewResolver(endpointResolver remotehttp.Resolver) Resolver {
	return &defaultResolver{endpointResolver: endpointResolver}
}

func (r *defaultResolver) ResolveOwner(krtctx krt.HandlerContext, owner ProviderOwner) (*ResolvedProviderRequest, error) {
	endpoint, err := ResolveDiscoveryEndpoint(krtctx, r.endpointResolver, owner.ID.Name, owner.DefaultNamespace, owner.Issuer, &owner.Discovery)
	if err != nil {
		return nil, err
	}

	return &ResolvedProviderRequest{
		OwnerID: owner.ID,
		Issuer:  owner.Issuer,
		Target:  *endpoint,
		TTL:     owner.TTL,
	}, nil
}
