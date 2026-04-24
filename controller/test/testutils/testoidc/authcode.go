// Package testoidc holds shared OIDC test fixtures used by both the dummy
// IdP testbox binary and the OIDC e2e suite, so the two halves cannot desync.
package testoidc

import "strings"

// HardcodedCode is the base authorization code the dummy IdP issues and the
// OIDC e2e suite expects. AuthorizationCodeForNonce appends a per-flow nonce.
const HardcodedCode = "fixed_auth_code_123"

// AuthorizationCodeForNonce produces the authorization code the dummy IdP
// will accept for the given nonce. When a nonce is present, the dummy IdP's
// /token handler requires the code to be "<HardcodedCode>.<nonce>".
func AuthorizationCodeForNonce(nonce string) string {
	if nonce == "" {
		return HardcodedCode
	}
	return HardcodedCode + "." + nonce
}

// NonceFromAuthorizationCode is the inverse of AuthorizationCodeForNonce.
// Returns "" when the code is not nonce-augmented.
func NonceFromAuthorizationCode(code string) string {
	prefix := HardcodedCode + "."
	if !strings.HasPrefix(code, prefix) {
		return ""
	}
	return strings.TrimPrefix(code, prefix)
}
