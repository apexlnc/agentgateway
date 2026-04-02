package oidc

import (
	"fmt"
	"strings"
	"time"

	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

func BuildProviderSource(
	kctx krt.HandlerContext,
	resolver *remotehttp.Resolver,
	policy types.NamespacedName,
	owner OwnerKey,
	authn *agentgateway.OIDCAuthentication,
) (ProviderSource, error) {
	ttl := 5 * time.Minute
	path := DefaultDiscoveryPath
	if authn.Discovery != nil {
		if authn.Discovery.CacheDuration != nil {
			ttl = authn.Discovery.CacheDuration.Duration
		}
		if authn.Discovery.Path != nil && *authn.Discovery.Path != "" {
			path = *authn.Discovery.Path
		}
	}

	if authn.Discovery != nil && authn.Discovery.BackendRef != nil {
		if resolver == nil {
			return ProviderSource{}, fmt.Errorf("oidc discovery backendRef requires a resolver")
		}

		ref := *authn.Discovery.BackendRef
		if ref.Kind == nil {
			ref.Kind = ptr.Of(gwv1.Kind(wellknown.ServiceKind))
		}
		resolved, err := resolver.Resolve(kctx, policy.Name, policy.Namespace, ref, path, string(authn.Issuer))
		if err != nil {
			return ProviderSource{}, err
		}
		return ProviderSource{
			OwnerKey:   owner,
			Issuer:     string(authn.Issuer),
			RequestKey: resolved.RequestKey,
			Target:     resolved.Target,
			TLSConfig:  resolved.TLSConfig,
			TTL:        ttl,
		}, nil
	}

	discoveryURL := fmt.Sprintf("%s/%s", strings.TrimRight(string(authn.Issuer), "/"), strings.TrimLeft(path, "/"))
	return ProviderSource{
		OwnerKey:   owner,
		Issuer:     string(authn.Issuer),
		RequestKey: remotehttp.BuildFetchKey(discoveryURL, string(authn.Issuer), nil),
		Target:     remotehttp.FetchTarget{URL: discoveryURL},
		TTL:        ttl,
	}, nil
}
