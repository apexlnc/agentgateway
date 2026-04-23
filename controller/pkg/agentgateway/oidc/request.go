package oidc

import (
	"time"

	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// ResolvedOidcRequest is the per-owner resolved discovery request, carrying the
// resolved target URL and TLS configuration for the OIDC discovery endpoint.
type ResolvedOidcRequest struct {
	OwnerID OidcOwnerID
	Target  remotehttp.ResolvedTarget
	TTL     time.Duration
}

// Resolver resolves a RemoteOidcOwner to a ResolvedOidcRequest.
type Resolver interface {
	ResolveOwner(krtctx krt.HandlerContext, owner RemoteOidcOwner) (*ResolvedOidcRequest, error)
}
