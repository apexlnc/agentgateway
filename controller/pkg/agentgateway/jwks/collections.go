package jwks

import (
	"sort"

	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

var fetchKeyIndexCollectionFunc = krt.WithIndexCollectionFromString(func(s string) remotehttp.FetchKey {
	return remotehttp.FetchKey(s)
})

type CollectionInputs struct {
	AgentgatewayPolicies krt.Collection[*agentgateway.AgentgatewayPolicy]
	Backends             krt.Collection[*agentgateway.AgentgatewayBackend]
	Resolver             Resolver
	KrtOpts              krtutil.KrtOptions
}

type Collections struct {
	PolicyOwners   krt.Collection[RemoteJwksOwner]
	BackendOwners  krt.Collection[RemoteJwksOwner]
	Owners         krt.Collection[RemoteJwksOwner]
	Sources        krt.Collection[JwksSource]
	SharedRequests krt.Collection[SharedJwksRequest]
}

func NewCollections(inputs CollectionInputs) Collections {
	policyOwners := krt.NewManyCollection(inputs.AgentgatewayPolicies, func(kctx krt.HandlerContext, policy *agentgateway.AgentgatewayPolicy) []RemoteJwksOwner {
		return OwnersFromPolicy(policy)
	}, inputs.KrtOpts.ToOptions("PolicyJwksOwners")...)
	backendOwners := krt.NewManyCollection(inputs.Backends, func(kctx krt.HandlerContext, backend *agentgateway.AgentgatewayBackend) []RemoteJwksOwner {
		return OwnersFromBackend(backend)
	}, inputs.KrtOpts.ToOptions("BackendJwksOwners")...)
	owners := krt.JoinCollection([]krt.Collection[RemoteJwksOwner]{policyOwners, backendOwners}, inputs.KrtOpts.ToOptions("JwksOwners")...)

	sources := krt.NewCollection(owners, func(kctx krt.HandlerContext, owner RemoteJwksOwner) *JwksSource {
		resolved, err := inputs.Resolver.ResolveOwner(kctx, owner)
		if err != nil {
			logger.Error("error generating remote jwks url or tls options", "error", err, "owner", owner.ID.String())
			return nil
		}

		return &JwksSource{
			OwnerKey:   resolved.OwnerID,
			RequestKey: resolved.Target.Key,
			Target:     resolved.Target.Target,
			TLSConfig:  resolved.Target.TLSConfig,
			TTL:        resolved.TTL,
			Issuer:     resolved.Issuer,
			Discovery:  resolved.Discovery,
		}
	}, inputs.KrtOpts.ToOptions("JwksSources")...)

	sourcesByRequestKey := krt.NewIndex(sources, "jwks-request-key", func(source JwksSource) []remotehttp.FetchKey {
		return []remotehttp.FetchKey{source.RequestKey}
	})
	requestGroups := sourcesByRequestKey.AsCollection(append(inputs.KrtOpts.ToOptions("JwksRequestGroups"), fetchKeyIndexCollectionFunc)...)
	sharedRequests := krt.NewCollection(requestGroups, func(kctx krt.HandlerContext, grouped krt.IndexObject[remotehttp.FetchKey, JwksSource]) *SharedJwksRequest {
		return collapseJwksSources(grouped)
	}, inputs.KrtOpts.ToOptions("JwksRequests")...)

	return Collections{
		PolicyOwners:   policyOwners,
		BackendOwners:  backendOwners,
		Owners:         owners,
		Sources:        sources,
		SharedRequests: sharedRequests,
	}
}

func collapseJwksSources(grouped krt.IndexObject[remotehttp.FetchKey, JwksSource]) *SharedJwksRequest {
	if len(grouped.Objects) == 0 {
		return nil
	}

	sources := append([]JwksSource(nil), grouped.Objects...)
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].OwnerKey.String() < sources[j].OwnerKey.String()
	})

	shared := SharedJwksRequest{
		RequestKey: grouped.Key,
		Target:     sources[0].Target,
		TLSConfig:  sources[0].TLSConfig,
		TTL:        sources[0].TTL,
		Issuer:     sources[0].Issuer,
		Discovery:  sources[0].Discovery,
	}
	for _, source := range sources[1:] {
		if source.Discovery != shared.Discovery {
			logger.Error("refusing to collapse jwks sources with mismatched discovery mode", "request_key", grouped.Key, "discovery", shared.Discovery, "conflicting_discovery", source.Discovery)
			return nil
		}
		if shared.Discovery {
			match, err := oidc.IssuersEquivalent(shared.Issuer, source.Issuer)
			if err != nil {
				logger.Error("invalid issuer while collapsing shared jwks request", "request_key", grouped.Key, "error", err)
				return nil
			}
			if !match {
				logger.Error("refusing to collapse discovery-backed jwks sources with mismatched issuers", "request_key", grouped.Key, "issuer", shared.Issuer, "conflicting_issuer", source.Issuer)
				return nil
			}
		}
		if source.TTL < shared.TTL {
			shared.TTL = source.TTL
		}
	}

	return &shared
}
