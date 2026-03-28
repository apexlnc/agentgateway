package oidc

import "fmt"

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
	if provider.Issuer != issuer {
		return fmt.Errorf("discovered issuer %q does not match configured issuer %q", provider.Issuer, issuer)
	}
	return ValidateProviderConfig(provider)
}
