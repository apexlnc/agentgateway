//! Shared configuration for Bedrock providers

use agent_core::prelude::Strng;
use agent_core::strng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// Model mapping configuration for deployment-level control
pub type ModelMappings = HashMap<String, String>;

/// Observability configuration for logging and telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ObservabilityConfig {
	/// Capture full reconstructed prompt text in traces/logs
	#[serde(default)]
	pub record_prompt_text: bool,

	/// Capture assistant completion text in traces/logs
	#[serde(default)]
	pub record_response_text: bool,

	/// Maximum characters to record for prompt/response (0 = unlimited)
	#[serde(default = "default_max_log_chars")]
	pub max_log_chars: usize,

	/// Include thinking blocks content in recorded completion
	#[serde(default)]
	pub include_thinking_text: bool,

	/// Include tool input/result JSON in prompt capture
	#[serde(default)]
	pub include_tool_io_text: bool,
}

impl Default for ObservabilityConfig {
	fn default() -> Self {
		Self {
			record_prompt_text: false,
			record_response_text: false,
			max_log_chars: 10000,
			include_thinking_text: false,
			include_tool_io_text: false,
		}
	}
}

/// Default configuration functions for advanced options
fn default_max_log_chars() -> usize {
	10000
}

/// Shared Bedrock configuration used by both Universal and Messages providers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Common {
	/// AWS region for Bedrock API calls
	pub region: Strng,

	/// Optional model override for Bedrock API path
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>,

	/// Guardrail configuration (enables guardrails if specified)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub guardrail_identifier: Option<Strng>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub guardrail_version: Option<Strng>,

	/// Model mapping configuration
	#[serde(skip_serializing_if = "Option::is_none")]
	pub model_mappings: Option<ModelMappings>,

	/// Additional model request fields
	#[serde(skip_serializing_if = "Option::is_none")]
	pub additional_model_fields: Option<serde_json::Value>,

	/// Optional list of anthropic_beta feature flags
	#[serde(default)]
	pub anthropic_beta: Option<Vec<String>>,

	/// Observability configuration
	#[serde(default)]
	pub observability: ObservabilityConfig,
}

impl Common {
	/// Get the Bedrock runtime host for this region
	pub fn host(&self) -> Strng {
		strng::format!("bedrock-runtime.{}.amazonaws.com", self.region)
	}

	/// Resolve to the Bedrock model id (provider override > mapping > passthrough)
	pub fn resolve_model_id(&self, requested: &str) -> String {
		// Provider-level model override takes precedence
		if let Some(m) = &self.model {
			return m.to_string();
		}
		// Check model mappings next
		if let Some(map) = &self.model_mappings
			&& let Some(m) = map.get(requested)
		{
			return m.clone();
		}
		// Default to passthrough
		requested.to_string()
	}

	/// Shared converse path builder
	pub fn converse_path(&self, model_id: &str, streaming: bool) -> Strng {
		if streaming {
			strng::format!("/model/{model_id}/converse-stream")
		} else {
			strng::format!("/model/{model_id}/converse")
		}
	}
}
