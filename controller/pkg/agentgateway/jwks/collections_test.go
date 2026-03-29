package jwks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

func TestCollapseJwksSourcesRejectsMismatchedDiscoverySemantics(t *testing.T) {
	target := remotehttp.FetchTarget{URL: "https://issuer.example/jwks"}

	tests := []struct {
		name    string
		sources []JwksSource
	}{
		{
			name: "mismatched discovery mode",
			sources: []JwksSource{
				{
					OwnerKey:   JwksOwnerID{Name: "one"},
					RequestKey: target.Key(),
					Target:     target,
					TTL:        5 * time.Minute,
					Discovery:  true,
					Issuer:     "https://issuer.example",
				},
				{
					OwnerKey:   JwksOwnerID{Name: "two"},
					RequestKey: target.Key(),
					Target:     target,
					TTL:        2 * time.Minute,
					Discovery:  false,
				},
			},
		},
		{
			name: "mismatched discovery issuer",
			sources: []JwksSource{
				{
					OwnerKey:   JwksOwnerID{Name: "one"},
					RequestKey: target.Key(),
					Target:     target,
					TTL:        5 * time.Minute,
					Discovery:  true,
					Issuer:     "https://issuer.example/one",
				},
				{
					OwnerKey:   JwksOwnerID{Name: "two"},
					RequestKey: target.Key(),
					Target:     target,
					TTL:        2 * time.Minute,
					Discovery:  true,
					Issuer:     "https://issuer.example/two",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shared := collapseJwksSources(krt.IndexObject[remotehttp.FetchKey, JwksSource]{
				Key:     target.Key(),
				Objects: tt.sources,
			})
			assert.Nil(t, shared)
		})
	}
}
