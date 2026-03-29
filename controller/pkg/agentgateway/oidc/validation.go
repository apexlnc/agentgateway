package oidc

import (
	"fmt"
	"strings"
)

func ValidateProviderConfig(provider ProviderConfig) error {
	if _, err := ParseIssuerURL(provider.Issuer); err != nil {
		return err
	}
	if _, err := ParseAbsoluteURL(provider.JwksURI, "jwks_uri"); err != nil {
		return err
	}
	if provider.AuthorizationEndpoint != "" {
		if _, err := ParseAbsoluteURL(provider.AuthorizationEndpoint, "authorization_endpoint"); err != nil {
			return err
		}
	}
	if provider.TokenEndpoint != "" {
		if _, err := ParseAbsoluteURL(provider.TokenEndpoint, "token_endpoint"); err != nil {
			return err
		}
	}
	if provider.EndSessionEndpoint != "" {
		if _, err := ParseAbsoluteURL(provider.EndSessionEndpoint, "end_session_endpoint"); err != nil {
			return err
		}
	}
	return nil
}

func ValidateProviderForIssuer(issuer string, provider ProviderConfig) error {
	match, err := IssuersEquivalent(issuer, provider.Issuer)
	if err != nil {
		return err
	}
	if !match {
		return fmt.Errorf("discovered issuer %q does not match configured issuer %q", provider.Issuer, issuer)
	}
	return ValidateProviderConfig(provider)
}

func IssuersEquivalent(left, right string) (bool, error) {
	leftURL, err := ParseIssuerURL(left)
	if err != nil {
		return false, err
	}
	rightURL, err := ParseIssuerURL(right)
	if err != nil {
		return false, err
	}

	return sameAuthority(leftURL, rightURL) &&
		strings.TrimRight(leftURL.EscapedPath(), "/") == strings.TrimRight(rightURL.EscapedPath(), "/"), nil
}
