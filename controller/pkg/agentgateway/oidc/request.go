package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

var (
	ErrResolverNotInitialized  = errors.New("remote http resolver hasn't been initialized")
	ErrDiscoveryNotInitialized = errors.New("oidc discovery transport hasn't been initialized")
)

func ResolveDiscoveryEndpoint(
	krtctx krt.HandlerContext,
	resolver remotehttp.Resolver,
	policyName, defaultNS, issuer string,
	discovery *agentgateway.OIDCDiscovery,
) (*remotehttp.ResolvedTarget, error) {
	if resolver == nil {
		return nil, ErrResolverNotInitialized
	}
	if discovery == nil {
		return nil, ErrDiscoveryNotInitialized
	}

	path, err := DiscoveryPathForIssuer(issuer)
	if err != nil {
		return nil, err
	}

	return resolver.Resolve(krtctx, remotehttp.ResolveInput{
		ParentName:       policyName,
		DefaultNamespace: defaultNS,
		BackendRef:       discovery.BackendRef,
		Path:             path,
	})
}

func DiscoveryPathForIssuer(issuer string) (string, error) {
	issuerURL, err := ParseIssuerURL(issuer)
	if err != nil {
		return "", err
	}

	issuerPath := issuerURL.EscapedPath()
	issuerPath = strings.TrimRight(issuerPath, "/")
	if issuerPath == "" {
		return "/.well-known/openid-configuration", nil
	}
	return issuerPath + "/.well-known/openid-configuration", nil
}

func DiscoveredJWKSTarget(issuer string, provider ProviderConfig) (remotehttp.FetchTarget, error) {
	if err := ValidateProviderForIssuer(issuer, provider); err != nil {
		return remotehttp.FetchTarget{}, err
	}

	jwksURL, err := ParseAbsoluteURL(provider.JwksURI, "jwks_uri")
	if err != nil {
		return remotehttp.FetchTarget{}, err
	}

	return remotehttp.FetchTarget{URL: jwksURL.String()}, nil
}

func URLsShareAuthority(left, right string) (bool, error) {
	leftURL, err := ParseAbsoluteURL(left, "left_url")
	if err != nil {
		return false, err
	}
	rightURL, err := ParseAbsoluteURL(right, "right_url")
	if err != nil {
		return false, err
	}
	return sameAuthority(leftURL, rightURL), nil
}

func ParseIssuerURL(raw string) (*url.URL, error) {
	issuerURL, err := ParseAbsoluteURL(raw, "issuer")
	if err != nil {
		return nil, err
	}
	if issuerURL.RawQuery != "" {
		return nil, fmt.Errorf("issuer %q must not include a query", raw)
	}
	return issuerURL, nil
}

func ParseAbsoluteURL(raw, field string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s %q: %w", field, raw, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("%s %q must be an absolute URL", field, raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s %q must not include user info", field, raw)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("%s %q must not include a fragment", field, raw)
	}
	return u, nil
}

func sameAuthority(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectivePort(left) == effectivePort(right)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}
