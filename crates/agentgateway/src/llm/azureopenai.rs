use agent_core::strng;
use agent_core::strng::Strng;

use crate::llm::RouteType;
use crate::*;

#[apply(schema!)]
pub struct Provider {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>, // this is the Azure OpenAI model deployment name
	pub host: Strng, // required
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub api_version: Option<Strng>, // optional, defaults to "v1"
}

impl super::Provider for Provider {
	const NAME: Strng = strng::literal!("azure.openai");
}

impl Provider {
	pub fn get_path_for_model(&self, route: RouteType, model: &str) -> Strng {
		match route {
			RouteType::Messages => strng::literal!("/anthropic/v1/messages"),
			RouteType::AnthropicTokenCount => strng::literal!("/anthropic/v1/messages/count_tokens"),
			RouteType::Embeddings => self.get_openai_path("embeddings", model),
			_ => self.get_openai_path("chat/completions", model),
		}
	}

	fn get_openai_path(&self, operation: &str, model: &str) -> Strng {
		let api_version = self.api_version();
		if api_version == "v1" {
			strng::format!("/openai/v1/{operation}")
		} else if api_version == "preview" && operation == "chat/completions" {
			// v1 preview API logic (only seen for chat/completions in original code)
			strng::format!("/openai/v1/{operation}?api-version=preview")
		} else {
			let model = self.model.as_deref().unwrap_or(model);
			strng::format!(
				"/openai/deployments/{}/{operation}?api-version={}",
				model,
				api_version
			)
		}
	}

	pub fn get_host(&self) -> Strng {
		self.host.clone()
	}

	fn api_version(&self) -> &str {
		self.api_version.as_deref().unwrap_or("v1")
	}
}
