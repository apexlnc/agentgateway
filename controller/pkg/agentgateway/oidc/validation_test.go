package oidc

import "testing"

func TestValidateProviderForIssuerAcceptsEquivalentIssuerURLs(t *testing.T) {
	err := ValidateProviderForIssuer("https://issuer.example/realms/team/", ProviderConfig{
		Issuer:  "https://issuer.example/realms/team",
		JwksURI: "https://issuer.example/keys",
	})
	if err != nil {
		t.Fatalf("ValidateProviderForIssuer() error = %v", err)
	}
}
