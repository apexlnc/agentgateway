//! Bedrock Converse API providers and utilities

use agent_core::prelude::Strng;
use agent_core::strng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "schema")]
use schemars::JsonSchema;

// Import for shared translation utilities
use crate::llm::messages;

pub mod anthropic;
pub mod types;
pub mod universal;

pub use types::{
	ContentBlock, ContentBlockDelta, ConverseErrorResponse, ConverseRequest, ConverseResponse,
	ConverseStreamOutput, StopReason,
};
pub use universal::Provider;

#[derive(Debug, Clone)]
pub struct AwsRegion {
	pub region: String,
}

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

/// Shared translation utilities for both Anthropic and Universal providers
/// 
/// This module centralizes mechanical translation functions that are stable 
/// across both providers, achieving "consistent output at choices[0].message.content" like LiteLLM.
pub mod translate {
    use crate::llm::{AIError, messages, universal};
    use crate::llm::bedrock::types as bedrock;
    use async_openai::types::Stop;

    /// Target format for stop reason translation
    #[derive(Debug, Clone, Copy)]
    pub enum StopReasonFormat {
        Anthropic,
        OpenAI,
    }

    /// Smart stop reason translator with configurable mappings
    pub fn translate_stop_reason<T>(reason: bedrock::StopReason, format: StopReasonFormat) -> T 
    where 
        T: From<StopReasonMapping>
    {
        use StopReasonMapping::*;
        
        let mapping = match (reason, format) {
            // Standard mappings (1:1)
            (bedrock::StopReason::EndTurn, StopReasonFormat::Anthropic) => AnthropicEndTurn,
            (bedrock::StopReason::EndTurn, StopReasonFormat::OpenAI) => OpenAIStop,
            
            (bedrock::StopReason::MaxTokens, StopReasonFormat::Anthropic) => AnthropicMaxTokens,
            (bedrock::StopReason::MaxTokens, StopReasonFormat::OpenAI) => OpenAILength,
            
            (bedrock::StopReason::StopSequence, StopReasonFormat::Anthropic) => AnthropicStopSequence,
            (bedrock::StopReason::StopSequence, StopReasonFormat::OpenAI) => OpenAIStop,
            
            (bedrock::StopReason::ToolUse, StopReasonFormat::Anthropic) => AnthropicToolUse,
            (bedrock::StopReason::ToolUse, StopReasonFormat::OpenAI) => OpenAIToolCalls,
            
            // Content filtering mappings (format-specific)
            (bedrock::StopReason::ContentFiltered, StopReasonFormat::Anthropic) => AnthropicRefusal,
            (bedrock::StopReason::ContentFiltered, StopReasonFormat::OpenAI) => OpenAIContentFilter,
            
            (bedrock::StopReason::GuardrailIntervened, StopReasonFormat::Anthropic) => AnthropicRefusal,
            (bedrock::StopReason::GuardrailIntervened, StopReasonFormat::OpenAI) => OpenAIContentFilter,
        };
        
        T::from(mapping)
    }

    /// Intermediate mapping enum for type conversion
    #[derive(Debug, Clone, Copy)]
    pub enum StopReasonMapping {
        AnthropicEndTurn,
        AnthropicMaxTokens,
        AnthropicStopSequence,
        AnthropicToolUse,
        AnthropicRefusal,
        
        OpenAIStop,
        OpenAILength,
        OpenAIToolCalls,
        OpenAIContentFilter,
    }

    /// Convert mapping to Anthropic format
    impl From<StopReasonMapping> for messages::StopReason {
        fn from(mapping: StopReasonMapping) -> Self {
            match mapping {
                StopReasonMapping::AnthropicEndTurn => messages::StopReason::EndTurn,
                StopReasonMapping::AnthropicMaxTokens => messages::StopReason::MaxTokens,
                StopReasonMapping::AnthropicStopSequence => messages::StopReason::StopSequence,
                StopReasonMapping::AnthropicToolUse => messages::StopReason::ToolUse,
                StopReasonMapping::AnthropicRefusal => messages::StopReason::Refusal,
                _ => panic!("Invalid mapping for Anthropic format"),
            }
        }
    }

    /// Convert mapping to OpenAI format
    impl From<StopReasonMapping> for universal::FinishReason {
        fn from(mapping: StopReasonMapping) -> Self {
            match mapping {
                StopReasonMapping::OpenAIStop => universal::FinishReason::Stop,
                StopReasonMapping::OpenAILength => universal::FinishReason::Length,
                StopReasonMapping::OpenAIToolCalls => universal::FinishReason::ToolCalls,
                StopReasonMapping::OpenAIContentFilter => universal::FinishReason::ContentFilter,
                _ => panic!("Invalid mapping for OpenAI format"),
            }
        }
    }

    /// Convenience functions matching existing naming patterns
    pub fn translate_stop_reason_to_anthropic(reason: bedrock::StopReason) -> messages::StopReason {
        translate_stop_reason(reason, StopReasonFormat::Anthropic)
    }

    pub fn translate_stop_reason_to_openai(reason: bedrock::StopReason) -> universal::FinishReason {
        translate_stop_reason(reason, StopReasonFormat::OpenAI)
    }

    /// Convert Bedrock usage to Anthropic format with cache token support
    pub fn usage_to_anthropic(usage: Option<bedrock::TokenUsage>) -> Result<messages::Usage, AIError> {
        match usage {
            Some(usage) => Ok(messages::Usage {
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cache_creation_input_tokens: usage.cache_write_input_tokens,
                cache_read_input_tokens: usage.cache_read_input_tokens,
                cache_creation: None, // Bedrock doesn't provide detailed cache creation breakdown
                server_tool_use: None, // Bedrock doesn't track server tool usage
                service_tier: None,   // Bedrock doesn't expose service tier
            }),
            None => Err(AIError::MissingField("usage information".into())),
        }
    }

    /// Convert Bedrock usage to OpenAI format
    pub fn usage_to_openai(usage: Option<bedrock::TokenUsage>) -> universal::Usage {
        match usage {
            Some(token_usage) => universal::Usage {
                prompt_tokens: token_usage.input_tokens,
                completion_tokens: token_usage.output_tokens,
                total_tokens: token_usage.total_tokens,
                prompt_tokens_details: None,
                completion_tokens_details: None,
            },
            None => universal::Usage::default(),
        }
    }

    /// Extract error type from HTTP status code and Bedrock error response
    /// Provides consistent error mapping aligned with Anthropic's error taxonomy
    pub fn extract_error_type(
        status_code: u16,
        error_response: Option<&bedrock::ConverseErrorResponse>,
    ) -> String {
        // Map common HTTP status codes to error types
        match status_code {
            400 => "invalid_request_error".to_string(),
            401 => "authentication_error".to_string(),
            403 => "permission_error".to_string(),
            404 => "not_found_error".to_string(),
            429 => "rate_limit_error".to_string(),
            500 => "api_error".to_string(),
            502..=504 => "api_error".to_string(),
            _ => {
                // Try to extract error type from Bedrock error response
                error_response
                    .and_then(|e| e.error_type.as_ref())
                    .map(|t| {
                        match t.as_str() {
                            "ValidationException" => "invalid_request_error",
                            "ThrottlingException" => "rate_limit_error",
                            "AccessDeniedException" => "permission_error",
                            "ResourceNotFoundException" => "not_found_error",
                            "InternalServerException" => "api_error",
                            "ServiceUnavailableException" => "overloaded_error",
                            _ => "api_error",
                        }
                        .to_string()
                    })
                    .unwrap_or_else(|| "api_error".to_string())
            }
        }
    }

    /// Convert Bedrock error response to Anthropic error format
    pub fn error_to_anthropic(
        bedrock_error: bedrock::ConverseErrorResponse,
        error_type: Option<&str>,
    ) -> Result<messages::MessagesErrorResponse, AIError> {
        let anthropic_error_type = error_type.unwrap_or("api_error").to_string();

        let anthropic_error = messages::ApiError {
            error_type: anthropic_error_type,
            message: bedrock_error.message,
        };

        Ok(messages::MessagesErrorResponse {
            response_type: "error".to_string(),
            error: anthropic_error,
        })
    }

    /// Convert Bedrock error response to OpenAI error format
    pub fn error_to_openai(
        bedrock_error: bedrock::ConverseErrorResponse,
    ) -> Result<universal::ChatCompletionErrorResponse, AIError> {
        Ok(universal::ChatCompletionErrorResponse {
            event_id: None,
            error: universal::ChatCompletionError {
                r#type: "invalid_request_error".to_string(),
                message: bedrock_error.message,
                param: None,
                code: None,
                event_id: None,
            },
        })
    }

    /// Request option normalization utilities
    pub mod options {
        use super::*;

        /// Extract max_tokens with proper precedence handling for OpenAI format
        /// Handles max_completion_tokens vs max_tokens precedence
        pub fn normalize_max_tokens_openai(req: &universal::Request) -> i32 {
            req.max_completion_tokens
                .unwrap_or(4096) as i32
        }

        /// Extract max_tokens for Anthropic format (direct passthrough)
        pub fn normalize_max_tokens_anthropic(max_tokens: u32) -> i32 {
            max_tokens as i32
        }

        /// Extract stop sequences for OpenAI format
        pub fn normalize_stop_sequences_openai(req: &universal::Request) -> Vec<String> {
            req.stop
                .as_ref()
                .map(|stop| match stop {
                    Stop::String(s) => vec![s.clone()],
                    Stop::StringArray(arr) => arr.clone(),
                })
                .unwrap_or_default()
        }

        /// Extract stop sequences for Anthropic format (direct passthrough)
        pub fn normalize_stop_sequences_anthropic(
            stop_sequences: Option<Vec<String>>,
        ) -> Option<Vec<String>> {
            stop_sequences
        }

        /// Build Bedrock InferenceConfiguration from normalized options
        pub fn build_inference_config(
            max_tokens: i32,
            temperature: Option<f32>,
            top_p: Option<f32>,
            stop_sequences: Option<Vec<String>>,
        ) -> bedrock::InferenceConfiguration {
            bedrock::InferenceConfiguration {
                max_tokens: Some(max_tokens),
                temperature,
                top_p,
                stop_sequences,
            }
        }
    }
}

/// Backward compatibility - implement From trait for stop reasons
impl From<StopReason> for messages::StopReason {
    fn from(bedrock_stop_reason: StopReason) -> Self {
        translate::translate_stop_reason_to_anthropic(bedrock_stop_reason)
    }
}