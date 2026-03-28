package jwks

import (
	"time"

	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

type ResolvedJwksRequest struct {
	OwnerID   JwksOwnerID
	Issuer    string
	Target    remotehttp.ResolvedTarget
	TTL       time.Duration
	Discovery bool
}

type Resolver interface {
	ResolveOwner(krtctx krt.HandlerContext, owner RemoteJwksOwner) (*ResolvedJwksRequest, error)
}

type defaultResolver struct {
	endpointResolver remotehttp.Resolver
}

func NewResolver(endpointResolver remotehttp.Resolver) Resolver {
	return &defaultResolver{endpointResolver: endpointResolver}
}

func (r *defaultResolver) ResolveOwner(krtctx krt.HandlerContext, owner RemoteJwksOwner) (*ResolvedJwksRequest, error) {
	var (
		endpoint  *remotehttp.ResolvedTarget
		err       error
		discovery bool
	)

	switch {
	case owner.Remote != nil:
		endpoint, err = ResolveEndpoint(krtctx, r.endpointResolver, owner.ID.Name, owner.DefaultNamespace, owner.Remote)
	case owner.Discovery != nil:
		endpoint, err = oidc.ResolveDiscoveryEndpoint(krtctx, r.endpointResolver, owner.ID.Name, owner.DefaultNamespace, owner.Issuer, owner.Discovery)
		discovery = true
	default:
		return nil, errRemoteProviderNotInitialized
	}
	if err != nil {
		return nil, err
	}

	return &ResolvedJwksRequest{
		OwnerID:   owner.ID,
		Issuer:    owner.Issuer,
		Target:    *endpoint,
		TTL:       owner.TTL,
		Discovery: discovery,
	}, nil
}
