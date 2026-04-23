use jsonwebtoken::jwk::JwkSet;
use secrecy::SecretString;

use super::local::{PreparedOidcPolicy, PreparedOidcProvider};
use super::{Error, OidcPolicy, PolicyId, ProviderEndpoint, RedirectUri};
use crate::http::oauth::TokenEndpointAuth;
use crate::http::sessionpersistence::Encoder;

/// OIDC provider configuration delivered to the dataplane via xDS after the
/// controller has resolved issuer discovery and pre-fetched the JWKS.
///
/// Unlike [`super::LocalOidcConfig`], this carries only fully-resolved data:
/// no `.well-known` fetch and no `jwks_uri` request happens at compile time.
/// The controller sources `client_secret` from the referenced Kubernetes
/// Secret and delivers it over xDS; only the ambient cookie encoder remains
/// out-of-band and never traverses the xDS channel.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedOidcConfig {
	pub policy_id: PolicyId,
	pub issuer: String,
	pub authorization_endpoint: ProviderEndpoint,
	pub token_endpoint: ProviderEndpoint,
	pub token_endpoint_auth: TokenEndpointAuth,
	pub jwks_inline: String,
	pub client_id: String,
	#[serde(serialize_with = "crate::serdes::ser_redact")]
	pub client_secret: SecretString,
	pub redirect_uri: RedirectUri,
	pub scopes: Vec<String>,
}

impl ResolvedOidcConfig {
	/// Compile into an [`OidcPolicy`] ready for runtime dispatch.
	///
	/// The encoder carries the cookie-crypto secret and must be sourced from
	/// the gateway's runtime configuration (never from xDS).
	pub fn compile(self, oidc_cookie_encoder: &Encoder) -> Result<OidcPolicy, Error> {
		let ResolvedOidcConfig {
			policy_id,
			issuer,
			authorization_endpoint,
			token_endpoint,
			token_endpoint_auth,
			jwks_inline,
			client_id,
			client_secret,
			redirect_uri,
			scopes,
		} = self;

		let id_token_jwks: JwkSet = serde_json::from_str(&jwks_inline).map_err(|e| {
			Error::Config(format!(
				"failed to parse inline oidc jwks delivered by xds: {e}"
			))
		})?;

		let prepared = PreparedOidcPolicy {
			provider: PreparedOidcProvider {
				issuer,
				authorization_endpoint,
				token_endpoint,
				token_endpoint_auth,
				id_token_jwks,
			},
			client_id,
			client_secret,
			redirect_uri,
			scopes,
		};

		prepared.compile(policy_id, oidc_cookie_encoder)
	}
}
