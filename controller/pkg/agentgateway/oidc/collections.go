package oidc

import (
	"sort"

	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/krtutil"
)

var fetchKeyIndexCollectionFunc = krt.WithIndexCollectionFromString(func(s string) remotehttp.FetchKey {
	return remotehttp.FetchKey(s)
})

type CollectionInputs struct {
	AgentgatewayPolicies krt.Collection[*agentgateway.AgentgatewayPolicy]
	Resolver             Resolver
	KrtOpts              krtutil.KrtOptions
}

type Collections struct {
	Owners         krt.Collection[ProviderOwner]
	Sources        krt.Collection[ProviderSource]
	SharedRequests krt.Collection[SharedProviderRequest]
}

func NewCollections(inputs CollectionInputs) Collections {
	owners := krt.NewManyCollection(inputs.AgentgatewayPolicies, func(kctx krt.HandlerContext, policy *agentgateway.AgentgatewayPolicy) []ProviderOwner {
		return OwnersFromPolicy(policy)
	}, inputs.KrtOpts.ToOptions("ProviderOwners")...)

	sources := krt.NewCollection(owners, func(kctx krt.HandlerContext, owner ProviderOwner) *ProviderSource {
		resolved, err := inputs.Resolver.ResolveOwner(kctx, owner)
		if err != nil {
			logger.Error("error generating oidc discovery url or tls options", "error", err, "owner", owner.ID.String())
			return nil
		}

		return &ProviderSource{
			OwnerKey:   resolved.OwnerID,
			Issuer:     resolved.Issuer,
			RequestKey: resolved.Target.Key,
			Target:     resolved.Target.Target,
			TLSConfig:  resolved.Target.TLSConfig,
			TTL:        resolved.TTL,
		}
	}, inputs.KrtOpts.ToOptions("ProviderSources")...)

	sourcesByRequestKey := krt.NewIndex(sources, "oidc-request-key", func(source ProviderSource) []remotehttp.FetchKey {
		return []remotehttp.FetchKey{source.RequestKey}
	})
	requestGroups := sourcesByRequestKey.AsCollection(append(inputs.KrtOpts.ToOptions("ProviderRequestGroups"), fetchKeyIndexCollectionFunc)...)
	sharedRequests := krt.NewCollection(requestGroups, func(kctx krt.HandlerContext, grouped krt.IndexObject[remotehttp.FetchKey, ProviderSource]) *SharedProviderRequest {
		return collapseProviderSources(grouped)
	}, inputs.KrtOpts.ToOptions("ProviderRequests")...)

	return Collections{
		Owners:         owners,
		Sources:        sources,
		SharedRequests: sharedRequests,
	}
}

func collapseProviderSources(grouped krt.IndexObject[remotehttp.FetchKey, ProviderSource]) *SharedProviderRequest {
	if len(grouped.Objects) == 0 {
		return nil
	}

	sources := append([]ProviderSource(nil), grouped.Objects...)
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].OwnerKey.String() < sources[j].OwnerKey.String()
	})

	shared := SharedProviderRequest{
		RequestKey: grouped.Key,
		Issuer:     sources[0].Issuer,
		Target:     sources[0].Target,
		TLSConfig:  sources[0].TLSConfig,
		TTL:        sources[0].TTL,
	}
	for _, source := range sources[1:] {
		match, err := IssuersEquivalent(shared.Issuer, source.Issuer)
		if err != nil {
			logger.Error("invalid issuer while collapsing shared oidc request", "request_key", grouped.Key, "error", err)
			return nil
		}
		if !match {
			logger.Error("refusing to collapse oidc sources with mismatched issuers", "request_key", grouped.Key, "issuer", shared.Issuer, "conflicting_issuer", source.Issuer)
			return nil
		}
		if source.TTL < shared.TTL {
			shared.TTL = source.TTL
		}
	}

	return &shared
}
