package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

func TestCollapseProviderSourcesRejectsMismatchedIssuers(t *testing.T) {
	target := remotehttp.FetchTarget{URL: "https://idp.internal/.well-known/openid-configuration"}

	shared := collapseProviderSources(krt.IndexObject[remotehttp.FetchKey, ProviderSource]{
		Key: target.Key(),
		Objects: []ProviderSource{
			{
				OwnerKey:   ProviderOwnerID{Name: "one"},
				Issuer:     "https://issuer.example/one",
				RequestKey: target.Key(),
				Target:     target,
				TTL:        5 * time.Minute,
			},
			{
				OwnerKey:   ProviderOwnerID{Name: "two"},
				Issuer:     "https://issuer.example/two",
				RequestKey: target.Key(),
				Target:     target,
				TTL:        2 * time.Minute,
			},
		},
	})

	assert.Nil(t, shared)
}
