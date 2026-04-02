package oidc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

const (
	testOIDCIssuer = "https://issuer.example.com"
	testOIDCJWKS   = `{"keys":[{"use":"sig","kty":"EC","kid":"kid-1","crv":"P-256","alg":"ES256","x":"WM7udBHga09KxC5kxq6GhrZ9M3Y8S9ZThq_XxsOcDhk","y":"xc7T4afkXmwjEbJMzQXCdQcU3PZKiLFlHl23GE1z4ug"}]}`
)

func testJWKSJSON(t *testing.T) string {
	t.Helper()

	var jwks jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal([]byte(testOIDCJWKS), &jwks))
	body, err := json.Marshal(jwks)
	require.NoError(t, err)
	return string(body)
}

func testTLSConfig(server *httptest.Server) *tls.Config {
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if tlsConfig == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return tlsConfig
}

func TestFetchProviderConfigRejectsIssuerMismatch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"issuer":"https://other.example.com",
			"authorization_endpoint":"https://issuer.example.com/authorize",
			"token_endpoint":"https://issuer.example.com/token",
			"jwks_uri":"https://issuer.example.com/jwks"
		}`))
	}))
	t.Cleanup(server.Close)

	_, err := fetchProviderConfig(context.Background(), server.Client(), ProviderSource{
		Issuer:     testOIDCIssuer,
		RequestKey: remotehttp.FetchKey("issuer-mismatch"),
		Target: remotehttp.FetchTarget{
			URL: server.URL,
		},
		TTL: time.Minute,
	})
	require.ErrorContains(t, err, "oidc discovery issuer mismatch")
}

func TestFetchProviderConfigUsesDiscoveryTLSForSameAuthorityJWKS(t *testing.T) {
	t.Parallel()

	jwksJSON := testJWKSJSON(t)
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(`{
				"issuer":"` + testOIDCIssuer + `",
				"authorization_endpoint":"` + testOIDCIssuer + `/authorize",
				"token_endpoint":"` + testOIDCIssuer + `/token",
				"jwks_uri":"` + server.URL + `/jwks",
				"token_endpoint_auth_methods_supported":["client_secret_post"]
			}`))
		case "/jwks":
			_, _ = w.Write([]byte(jwksJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	cfg, err := fetchProviderConfig(context.Background(), http.DefaultClient, ProviderSource{
		Issuer:     testOIDCIssuer,
		RequestKey: remotehttp.FetchKey("same-authority"),
		Target: remotehttp.FetchTarget{
			URL: server.URL + "/.well-known/openid-configuration",
		},
		TLSConfig: testTLSConfig(server),
		TTL:       time.Minute,
	})
	require.NoError(t, err)
	require.Equal(t, "clientSecretPost", cfg.TokenEndpointAuth)
	require.Equal(t, server.URL+"/jwks", cfg.JwksURI)
	require.JSONEq(t, jwksJSON, cfg.JwksInline)
}

func TestFetchProviderConfigAllowsCrossAuthorityHTTPSJWKS(t *testing.T) {
	t.Parallel()

	jwksJSON := testJWKSJSON(t)
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(jwksJSON))
	}))
	t.Cleanup(jwksServer.Close)

	discoveryServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"issuer":"` + testOIDCIssuer + `",
			"authorization_endpoint":"` + testOIDCIssuer + `/authorize",
			"token_endpoint":"` + testOIDCIssuer + `/token",
			"jwks_uri":"` + jwksServer.URL + `/jwks",
			"token_endpoint_auth_methods_supported":["client_secret_basic"]
		}`))
	}))
	t.Cleanup(discoveryServer.Close)

	cfg, err := fetchProviderConfig(context.Background(), jwksServer.Client(), ProviderSource{
		Issuer:     testOIDCIssuer,
		RequestKey: remotehttp.FetchKey("cross-authority"),
		Target: remotehttp.FetchTarget{
			URL: discoveryServer.URL,
		},
		TLSConfig: testTLSConfig(discoveryServer),
		TTL:       time.Minute,
	})
	require.NoError(t, err)
	require.Equal(t, "clientSecretBasic", cfg.TokenEndpointAuth)
	require.Equal(t, jwksServer.URL+"/jwks", cfg.JwksURI)
	require.JSONEq(t, jwksJSON, cfg.JwksInline)
}

func TestFetchProviderConfigRejectsCrossAuthorityHTTPJWKS(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"issuer":"` + testOIDCIssuer + `",
			"authorization_endpoint":"` + testOIDCIssuer + `/authorize",
			"token_endpoint":"` + testOIDCIssuer + `/token",
			"jwks_uri":"http://jwks.example.com/keys"
		}`))
	}))
	t.Cleanup(server.Close)

	_, err := fetchProviderConfig(context.Background(), http.DefaultClient, ProviderSource{
		Issuer:     testOIDCIssuer,
		RequestKey: remotehttp.FetchKey("cross-authority-http"),
		Target: remotehttp.FetchTarget{
			URL: server.URL,
		},
		TLSConfig: testTLSConfig(server),
		TTL:       time.Minute,
	})
	require.ErrorContains(t, err, "cross-authority jwks uri must use https")
}

func TestParseTokenEndpointAuthMethodsDefaultsAndRejectsUnsupported(t *testing.T) {
	t.Parallel()

	auth, err := parseTokenEndpointAuthMethods(nil)
	require.NoError(t, err)
	require.Equal(t, "clientSecretBasic", auth)

	auth, err = parseTokenEndpointAuthMethods([]string{"private_key_jwt", "client_secret_post"})
	require.NoError(t, err)
	require.Equal(t, "clientSecretPost", auth)

	_, err = parseTokenEndpointAuthMethods([]string{"private_key_jwt", "none"})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "clientSecretBasic") || strings.Contains(err.Error(), "clientSecretPost"))
}
