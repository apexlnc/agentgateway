use agent_core::prelude::Strng;
use agent_core::strng;
use bytes::Bytes;
use chrono;
use rand::Rng;
use tracing::{trace, debug};

use crate::http::Response;
use crate::llm::bedrock::types::{
	ContentBlock, ContentBlockDelta, ConverseErrorResponse, ConverseRequest, ConverseResponse,
	ConverseStreamOutput, StopReason,
};
use crate::llm::{AIError, BackendAdapter, LLMResponse, universal};
use crate::telemetry::log::AsyncLog;
use crate::*;

// Macro to reduce serde boilerplate for Bedrock types
macro_rules! bedrock_struct {
    ($(#[$meta:meta])* $vis:vis struct $name:ident { $($fields:tt)* }) => {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "schema", derive(JsonSchema))]
        $(#[$meta])*
        $vis struct $name {
            $($fields)*
        }
    };
}

macro_rules! bedrock_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($variants:tt)* }) => {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        #[cfg_attr(feature = "schema", derive(JsonSchema))]
        $(#[$meta])*
        $vis enum $name {
            $($variants)*
        }
    };
}


#[derive(Debug, Clone)]
pub struct AwsRegion {
	pub region: String,
}

bedrock_struct! {
#[serde(rename_all = "camelCase")]
pub struct Provider {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>, // Optional: model override for Bedrock API path
	pub region: Strng, // Required: AWS region
	#[serde(skip_serializing_if = "Option::is_none")]
	pub guardrail_identifier: Option<Strng>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub guardrail_version: Option<Strng>,
}
}

impl super::Provider for Provider {
	const NAME: Strng = strng::literal!("bedrock");
}

// Implement BackendAdapter trait for Provider
impl BackendAdapter for Provider {
	type BReq = ConverseRequest;
	type BResp = ConverseResponse;

	/// Convert OpenAI request to Bedrock ConverseRequest format
	fn to_backend(&self, req: &universal::Request) -> Result<Self::BReq, AIError> {
		// Use provider's model if configured, otherwise use request model
		let model = if let Some(provider_model) = &self.model {
			provider_model.to_string()
		} else if let Some(req_model) = &req.model {
			req_model.clone()
		} else {
			return Err(AIError::MissingField("model not specified".into()));
		};

		// Use direct Universal → Bedrock conversion
		translate_request(req, self, &model)
	}

	/// Convert Bedrock ConverseResponse to OpenAI response format
	fn from_backend(&self, bresp: Self::BResp, model_id: &str) -> Result<universal::Response, AIError> {
		// Use existing translate_response method that already handles Bedrock → OpenAI conversion
		// Note: BackendAdapter doesn't have access to original request, so default to not excluding reasoning
		translate_response(bresp, self.model.as_deref().unwrap_or(model_id), false)
	}
}

impl Provider {

	pub async fn process_error(
		&self,
		bytes: &Bytes,
	) -> Result<universal::ChatCompletionErrorResponse, AIError> {
		debug!("Bedrock: Received error response ({} bytes): {}", bytes.len(), String::from_utf8_lossy(bytes));
		let resp =
			serde_json::from_slice::<ConverseErrorResponse>(bytes).map_err(AIError::ResponseParsing)?;
		debug!("Bedrock: Parsed error response: {:?}", resp);
		translate_error(resp)
	}

	/// Process streaming responses with direct Anthropic Messages API SSE output
	pub(super) async fn process_streaming_messages(
		&self,
		log: AsyncLog<LLMResponse>,
		rate_limit: crate::store::LLMResponsePolicies,
		resp: Response,
		model: &str,
	) -> Response {
		// Extract message ID from AWS Request ID header if available, otherwise use random ID
		// Always prefix with msg_ for Anthropic client compatibility
		let message_id = resp
			.headers()
			.get(crate::http::x_headers::X_AMZN_REQUESTID)
			.and_then(|s| s.to_str().ok().map(|s| format!("msg_{}", s)))
			.unwrap_or_else(|| format!("msg_{:016x}", rand::rng().random::<u64>()));

		let (parts, body) = resp.into_parts();
		let anthropic_body = streaming::AnthropicStreamBody::new(
			body,
			message_id,
			self.model.as_deref().unwrap_or(model).to_string(),
			log,
			Some(rate_limit),
		);
		let mut sse_response = Response::from_parts(parts, crate::http::Body::new(anthropic_body));
		let headers = sse_response.headers_mut();
		headers.insert(
			"content-type",
			http::HeaderValue::from_static("text/event-stream; charset=utf-8"),
		);
		headers.insert("cache-control", http::HeaderValue::from_static("no-cache"));
		headers.insert("connection", http::HeaderValue::from_static("keep-alive"));
		headers.insert("x-accel-buffering", http::HeaderValue::from_static("no"));
		headers.remove("content-length");

		sse_response
	}

	pub(super) async fn process_streaming(
		&self,
		log: AsyncLog<LLMResponse>,
		resp: Response,
		model: &str,
	) -> Response {
		let model = self.model.as_deref().unwrap_or(model).to_string();
		// Bedrock doesn't return an ID, so get one from the request... if we can
		let message_id = resp
			.headers()
			.get(http::x_headers::X_AMZN_REQUESTID)
			.and_then(|s| s.to_str().ok().map(|s| s.to_owned()))
			.unwrap_or_else(|| format!("{:016x}", rand::rng().random::<u64>()));
		// This is static for all chunks!
		let created = chrono::Utc::now().timestamp() as u32;
		resp.map(move |b| {
			let mut saw_token = false;

			parse::aws_sse::transform::<universal::StreamResponse>(b, move |f| {
				let res = types::ConverseStreamOutput::deserialize(f).ok()?;
				let mk = |choices: Vec<universal::ChatChoiceStream>, usage: Option<universal::Usage>| {
					Some(universal::StreamResponse {
						id: message_id.clone(),
						model: model.clone(),
						object: "chat.completion.chunk".to_string(),
						system_fingerprint: None,
						service_tier: None,
						created,
						choices,
						usage,
					})
				};

				match res {
					ConverseStreamOutput::ContentBlockStart(start) => {
						match &start.start {
							types::ContentBlockStart::ToolUse { tool_use: _ } => {
								// Tool calls are not supported in streaming format, skip
								None
							},
							_ => None, // Text and other starts don't need special handling
						}
					},
					ConverseStreamOutput::ContentBlockDelta(d) => {
						if !saw_token {
							saw_token = true;
							log.non_atomic_mutate(|r| {
								r.first_token = Some(Instant::now());
							});
						}
						match &d.delta {
							ContentBlockDelta::Text { text: s } => {
								let choice = universal::ChatChoiceStream {
									index: 0,
									logprobs: None,
									delta: universal::StreamResponseDelta {
										role: None,
										content: Some(s.clone()),
										refusal: None,
										#[allow(deprecated)]
										function_call: None,
										tool_calls: None,
									},
									finish_reason: None,
								};
								mk(vec![choice], None)
							},
							ContentBlockDelta::ToolUse { tool_use: _ } => {
								// debug!("Bedrock: Processing ToolUse delta: {:?}", tool_use);
								// Convert tool use delta to OpenAI streaming format
								// This will accumulate JSON and emit tool_calls when complete
								// For now, skip individual deltas and handle in ContentBlockStop
								None
							},
							_ => None,
						}
					},
					ConverseStreamOutput::ContentBlockStop(_) => {
						// Clean up accumulator for this block but don't emit anything
						// tool_accumulators.remove(&stop.content_block_index);
						None
					},
					ConverseStreamOutput::MessageStart(start) => {
						// Just send a blob with the role
						let choice = universal::ChatChoiceStream {
							index: 0,
							logprobs: None,
							delta: universal::StreamResponseDelta {
								role: Some(match start.role {
									types::Role::Assistant => universal::Role::Assistant,
									types::Role::User => universal::Role::User,
								}),
								content: None,
								refusal: None,
								#[allow(deprecated)]
								function_call: None,
								tool_calls: None,
							},
							finish_reason: None,
						};
						mk(vec![choice], None)
					},
					ConverseStreamOutput::MessageStop(stop) => {
						let finish_reason = Some(reasons::to_universal(&stop.stop_reason));

						// Just send a blob with the finish reason
						let choice = universal::ChatChoiceStream {
							index: 0,
							logprobs: None,
							delta: universal::StreamResponseDelta {
								role: None,
								content: None,
								refusal: None,
								#[allow(deprecated)]
								function_call: None,
								tool_calls: None,
							},
							finish_reason,
						};
						mk(vec![choice], None)
					},
					ConverseStreamOutput::Metadata(metadata) => {
						if let Some(usage) = metadata.usage {
							log.non_atomic_mutate(|r| {
								r.output_tokens = Some(usage.output_tokens as u64);
								r.input_tokens_from_response = Some(usage.input_tokens as u64);
								r.total_tokens = Some(usage.total_tokens as u64);
							});

							mk(
								vec![],
								Some(universal::Usage {
									prompt_tokens: usage.input_tokens,
									completion_tokens: usage.output_tokens,
									total_tokens: usage.total_tokens,
									prompt_tokens_details: None,
									completion_tokens_details: None,
								}),
							)
						} else {
							None
						}
					},
					ConverseStreamOutput::InternalServerException(_) |
					ConverseStreamOutput::ModelStreamErrorException(_) |
					ConverseStreamOutput::ServiceUnavailableException(_) |
					ConverseStreamOutput::ThrottlingException(_) |
					ConverseStreamOutput::ValidationException(_) |
					ConverseStreamOutput::ModelTimeoutException(_) => {
						// Skip error events in OpenAI streaming format
						None
					},
				}
			})
		})
	}

	pub fn get_path_for_model(&self, streaming: bool, model: &str) -> Strng {
		let model = self.model.as_deref().unwrap_or(model);
		if streaming {
			strng::format!("/model/{model}/converse-stream")
		} else {
			strng::format!("/model/{model}/converse")
		}
	}

	pub fn get_host(&self) -> Strng {
		strng::format!("bedrock-runtime.{}.amazonaws.com", self.region)
	}
}

/// Centralized stop reason and error handling
mod reasons {
	use super::StopReason;
	use crate::llm::universal;

	/// Convert Bedrock stop reason to Universal finish reason
	pub fn to_universal(s: &StopReason) -> universal::FinishReason {
		match s {
			StopReason::EndTurn => universal::FinishReason::Stop,
			StopReason::MaxTokens => universal::FinishReason::Length,
			StopReason::StopSequence => universal::FinishReason::Stop,
			StopReason::ToolUse => universal::FinishReason::ToolCalls,
			StopReason::ContentFiltered | StopReason::GuardrailIntervened => universal::FinishReason::ContentFilter,
		}
	}

	/// Convert Bedrock stop reason to Anthropic stop_reason string (for SSE bridge)
	pub fn to_anthropic(s: &StopReason) -> &'static str {
		match s {
			StopReason::EndTurn => "end_turn",
			StopReason::MaxTokens => "max_tokens",
			StopReason::StopSequence => "stop_sequence",
			StopReason::ToolUse => "tool_use",
			// Best-effort mapping for safety stops
			StopReason::ContentFiltered | StopReason::GuardrailIntervened => "stop_sequence",
		}
	}
}

/// Centralized Bedrock streaming error handling
#[derive(Debug, Clone, Copy)]
pub enum BedrockStreamError {
	InternalServer,
	ModelStreamError,
	ServiceUnavailable,
	Throttling,
	Validation,
	ModelTimeout,
}

impl BedrockStreamError {
	pub fn from_event_type(s: &str) -> Option<Self> {
		use BedrockStreamError::*;
		Some(match s {
			"internalServerException" => InternalServer,
			"modelStreamErrorException" => ModelStreamError,
			"serviceUnavailableException" => ServiceUnavailable,
			"throttlingException" => Throttling,
			"validationException" => Validation,
			"modelTimeoutException" => ModelTimeout,
			_ => return None,
		})
	}

	pub fn to_anthropic_error(self) -> streaming::ErrorResponse {
		use BedrockStreamError::*;
		let (error_type, message) = match self {
			InternalServer => ("internal_server_exception", "Internal server error"),
			ModelStreamError => ("model_stream_error_exception", "Model stream error"),
			ServiceUnavailable => ("service_unavailable_exception", "Service unavailable"),
			Throttling => ("throttling_exception", "Throttling error"),
			Validation => ("validation_exception", "Validation error"),
			ModelTimeout => ("model_timeout_exception", "Model timeout"),
		};
		streaming::ErrorResponse {
			error_type: error_type.to_string(),
			message: message.to_string(),
		}
	}
}

pub(super) fn translate_error(
	resp: ConverseErrorResponse,
) -> Result<universal::ChatCompletionErrorResponse, AIError> {
	Ok(universal::ChatCompletionErrorResponse {
		event_id: None,
		error: universal::ChatCompletionError {
			r#type: "invalid_request_error".to_string(),
			message: resp.message,
			param: None,
			code: None,
			event_id: None,
		},
	})
}

pub(super) fn translate_response(
	resp: ConverseResponse,
	model: &str,
	exclude_reasoning: bool,
) -> Result<universal::Response, AIError> {
	// Get the output content from the response
	let output = resp.output.ok_or(AIError::IncompleteResponse)?;

	// Extract the message from the output
	let message = match output {
		types::ConverseOutput::Message { message: msg } => msg,
	};
	// Convert Bedrock content blocks to Universal message content
	// Separate text content from reasoning content
	let mut tool_calls: Vec<universal::MessageToolCall> = Vec::new();
	let mut text_parts: Vec<String> = Vec::new();
	let mut reasoning_details: Vec<universal::ReasoningDetail> = Vec::new();

	for block in &message.content {
		match block {
			ContentBlock::Text(text) => {
				if !text.trim().is_empty() {
					text_parts.push(text.clone());
				}
			},
			ContentBlock::Image { .. } => continue, // Skip images in response for now
			ContentBlock::ToolResult(_) => {
				// There should not be a ToolResult in the response, only in the request
				continue;
			},
			ContentBlock::ToolUse(tu) => {
				let Some(args) = serde_json::to_string(&tu.input).ok() else {
					continue;
				};
				tool_calls.push(universal::MessageToolCall {
					id: tu.tool_use_id.clone(),
					r#type: universal::ToolType::Function,
					function: universal::FunctionCall {
						name: tu.name.clone(),
						arguments: args,
					},
				});
			},
			ContentBlock::Document(_) => continue, // Skip documents for now
			ContentBlock::CachePoint(_) => continue, // Skip cache points
			ContentBlock::ReasoningContent(reasoning) => {
				// Handle reasoning content separately - DON'T add to text_parts
				if !exclude_reasoning {
					if let Some(reasoning_text) = &reasoning.reasoning_text {
						if !reasoning_text.text.trim().is_empty() {
							reasoning_details.push(universal::ReasoningDetail {
								text: Some(reasoning_text.text.clone()),
								signature: reasoning_text.signature.clone(),
							});
						}
					}
				}
				// Note: redacted_content is typically base64 encoded and not useful as text
			}
		};
	}

	// Concatenate text parts and reasoning details with newlines
	let all_content_parts = text_parts;

	// Add reasoning content if present and not excluded
	debug!("Bedrock: Found {} reasoning details, exclude_reasoning={}", reasoning_details.len(), exclude_reasoning);
	if !exclude_reasoning {
		for detail in reasoning_details {
			if let Some(reasoning_text) = detail.text {
				if !reasoning_text.trim().is_empty() {
					debug!("Bedrock: Including reasoning text in response ({} chars)", reasoning_text.len());
					// Don't include reasoning in text content - thinking should be handled separately
					// all_content_parts.push(format!("[REASONING]\n{}", reasoning_text));
				}
			}
		}
	}

	let content = if all_content_parts.is_empty() {
		None
	} else {
		Some(all_content_parts.join("\n\n"))
	};

	let message = universal::ResponseMessage {
		role: universal::Role::Assistant,
		content,
		tool_calls: if tool_calls.is_empty() {
			None
		} else {
			Some(tool_calls)
		},
		#[allow(deprecated)]
		function_call: None,
		refusal: None,
		audio: None,
	};
	let finish_reason = resp.stop_reason.as_ref().map(reasons::to_universal);
	// Only one choice for Bedrock
	let choice = universal::ChatChoice {
		index: 0,
		message,
		finish_reason,
		logprobs: None,
	};
	let choices = vec![choice];

	// Convert usage from Bedrock format to Universal format (if present)
	let usage = resp.usage.map(|token_usage| universal::Usage {
		prompt_tokens: token_usage.input_tokens,
		completion_tokens: token_usage.output_tokens,
		total_tokens: token_usage.total_tokens,
		// Keep existing structure - cache usage will be handled via provider metadata
		prompt_tokens_details: None,
		completion_tokens_details: None,
	});

	// Generate a unique ID since it's not provided in the response
	let id = format!("bedrock-{}", chrono::Utc::now().timestamp_millis());

	// Log guardrail trace information if present
	if let Some(trace) = &resp.trace
		&& let Some(guardrail_trace) = &trace.guardrail
	{
		trace!("Bedrock guardrail trace: {:?}", guardrail_trace);
	}

	Ok(universal::Response {
		id,
		object: "chat.completion".to_string(),
		created: chrono::Utc::now().timestamp() as u32,
		model: model.to_string(),
		choices,
		usage,
		service_tier: None,
		system_fingerprint: None,
	})
}


/// Aggregate Tool messages into ToolResultBlocks for Bedrock
/// Returns (tool_results, orphaned_tools) where orphaned_tools are tool messages that don't match expected IDs
fn aggregate_tool_results(
	messages: &[universal::RequestMessage],
	start_idx: &mut usize,
	valid_tool_ids: &std::collections::HashSet<String>,
	tool_results_meta: Option<&std::collections::HashMap<String, bool>>,
) -> (Vec<types::ToolResultBlock>, Vec<String>) {
	use std::collections::BTreeMap;
	let mut tool_results_by_id: BTreeMap<String, types::ToolResultBlock> = BTreeMap::new();
	let mut orphaned_tools = Vec::new();

	while *start_idx < messages.len() {
		if let universal::RequestMessage::Tool(tool_msg) = &messages[*start_idx] {
			let chunk_text = match &tool_msg.content {
				universal::RequestToolMessageContent::Text(t) => t.clone(),
				universal::RequestToolMessageContent::Array(parts) => parts.iter()
					.map(|p| match p {
						async_openai::types::ChatCompletionRequestToolMessageContentPart::Text(tp) => tp.text.as_str(),
					})
					.collect::<Vec<_>>()
					.join("\n"),
			};

			let id = tool_msg.tool_call_id.clone();

			// Check if this tool_id is valid for the current context
			if !valid_tool_ids.is_empty() && !valid_tool_ids.contains(&id) {
				// This tool doesn't match expected IDs - treat as orphaned
				debug!("Bedrock: Tool message '{}' at index {} doesn't match expected tool_calls", id, *start_idx);
				orphaned_tools.push(format!("[Tool: {}]\n{}", id, chunk_text));
				*start_idx += 1;
				continue;
			}

			let status = tool_results_meta
				.and_then(|m| m.get(&id))
				.map(|is_error| if *is_error { types::ToolResultStatus::Error } else { types::ToolResultStatus::Success });

			let entry = tool_results_by_id.entry(id.clone()).or_insert_with(|| types::ToolResultBlock {
				tool_use_id: id.clone(),
				content: Vec::new(),
				status: status.clone(),
			});

			// Prefer Error if any chunk marks it as Error
			entry.status = match (entry.status.take(), status) {
				(Some(types::ToolResultStatus::Error), _) | (_, Some(types::ToolResultStatus::Error)) => {
					Some(types::ToolResultStatus::Error)
				}
				(Some(types::ToolResultStatus::Success), Some(types::ToolResultStatus::Success)) => {
					Some(types::ToolResultStatus::Success)
				}
				(s @ Some(_), None) | (None, s @ Some(_)) => s,
				(None, None) => None,
			};

			entry.content.push(ContentBlock::Text(chunk_text));
			*start_idx += 1;
		} else {
			break;
		}
	}

	(tool_results_by_id.into_values().collect(), orphaned_tools)
}

/// Convert Universal request directly to Bedrock ConverseRequest format
pub(super) fn translate_request(req: &universal::Request, provider: &Provider, model: &str) -> Result<ConverseRequest, AIError> {
	debug!("Bedrock: Starting translation for {} messages, reasoning: {:?}",
		req.messages.len(), req.reasoning);
	if let Some(reasoning) = &req.reasoning {
		debug!("Bedrock: Received reasoning config from Messages API - enabled: {}, max_tokens: {:?}", reasoning.enabled, reasoning.max_tokens);
	}

	// Extract tool_results_meta from providers bag for proper ToolResult.status handling
	let tool_results_meta = req.providers
		.as_ref()
		.and_then(|providers| providers.get("anthropic"))
		.and_then(|anthropic| anthropic.get("tool_results_meta"))
		.and_then(|meta| meta.as_object())
		.map(|obj| {
			obj.iter()
				.filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b)))
				.collect::<std::collections::HashMap<String, bool>>()
		});


	// Build additionalModelRequestFields for Bedrock
	let mut additional_fields = serde_json::Map::new();

	// Extract anthropic beta headers from providers bag (for experimental features only)
	if let Some(beta_array) = req.providers
		.as_ref()
		.and_then(|providers| providers.get("anthropic"))
		.and_then(|anthropic| anthropic.get("headers"))
		.and_then(|headers| headers.get("beta"))
		.and_then(|beta| beta.as_array())
		.filter(|beta_array| !beta_array.is_empty())
	{
		additional_fields.insert("anthropic_beta".to_string(), serde_json::Value::Array(beta_array.clone()));
	}

	// Handle legitimate Anthropic thinking configuration -> Bedrock additionalModelRequestFields
	if let Some(reasoning) = &req.reasoning {
		debug!("Bedrock: Found reasoning config - enabled: {}, max_tokens: {:?}", reasoning.enabled, reasoning.max_tokens);
		if reasoning.enabled {
			// Check if conversation has assistant messages without thinking blocks
			// Bedrock requires assistant messages to start with thinking blocks when thinking is enabled
			let has_incompatible_assistant = req.messages.iter().any(|msg| {
				if let universal::RequestMessage::Assistant(assistant) = msg {
					// Check if this assistant has content/tools but lacks thinking
					let has_content = !universal::message_text(msg).unwrap_or("").is_empty();
					let has_tools = assistant.tool_calls.as_ref().is_some_and(|calls| !calls.is_empty());

					if has_content || has_tools {
						// This assistant message would need a thinking block
						// TODO: Check for actual ReasoningContent blocks in conversation history
						// For now, conservatively assume no thinking blocks exist
						return true;
					}
				}
				false
			});

			if has_incompatible_assistant {
				debug!("Bedrock: Found {} incompatible assistant messages, will enable thinking anyway and let Bedrock handle it",
					req.messages.iter().filter(|msg| matches!(msg, universal::RequestMessage::Assistant(_))).count());
			}

			// Always enable thinking when requested - user experience over Bedrock constraints
			debug!("Bedrock: Enabling thinking as requested by user");

			// Calculate budget_tokens from max_tokens or default
			let budget_tokens = if let Some(max) = reasoning.max_tokens {
				max
			} else {
				// Default to reasonable budget based on request max_tokens
				let request_max = universal::max_tokens(req) as u32;
				(request_max / 2).max(1024) // 50% for reasoning, minimum 1024
			};

			// Bedrock supports thinking via additionalModelRequestFields
			debug!("Bedrock: Enabling thinking with budget_tokens={}", budget_tokens);
			additional_fields.insert("thinking".to_string(), serde_json::json!({
				"type": "enabled",
				"budget_tokens": budget_tokens
			}));
		}
	}

	let additional_model_request_fields = if additional_fields.is_empty() {
		None
	} else {
		Some(serde_json::Value::Object(additional_fields))
	};


	// Extract system messages from Universal format
	let mut system_text = Vec::new();
	let mut messages: Vec<types::Message> = Vec::new();

	// Coalesce messages following Anthropic pattern: Assistant(tool_use) → User(tool_result + text)
	let mut i = 0;
	while i < req.messages.len() {
		match &req.messages[i] {
			universal::RequestMessage::System(sys_msg) => {
				let text = match &sys_msg.content {
					universal::RequestSystemMessageContent::Text(t) => t.clone(),
					universal::RequestSystemMessageContent::Array(blocks) => {
						blocks.iter()
							.map(|block| match block {
								async_openai::types::ChatCompletionRequestSystemMessageContentPart::Text(text_part) => {
									text_part.text.as_str()
								}
							})
							.collect::<Vec<_>>()
							.join("\n")
					}
				};
				system_text.push(text);
				i += 1;
			},
			universal::RequestMessage::Assistant(assistant_msg) => {
				// Convert assistant message
				let mut content = convert_openai_message_to_bedrock_content(
					&req.messages[i],
					tool_results_meta.as_ref()
				);
				// Always include Assistant messages, especially those with tool_calls
				// Empty content check could miss tool_calls without text content
				let has_tool_calls = assistant_msg.tool_calls.as_ref().is_some_and(|calls| !calls.is_empty());

				// Re-emit thinking blocks if thinking is enabled and this assistant has tool calls
				let reasoning_enabled = req.reasoning.as_ref().map(|r| r.enabled).unwrap_or(false);
				if reasoning_enabled && has_tool_calls {
					// Look up preserved thinking blocks from the original assistant message
					if let Some(preserved_thinking) = extract_thinking_blocks_for_assistant(req, assistant_msg) {
						debug!("Bedrock: Re-emitting {} thinking blocks for assistant with tool calls", preserved_thinking.len());
						// Prepend thinking blocks to content (they must come first)
						let mut thinking_content = preserved_thinking;
						thinking_content.extend(content);
						content = thinking_content;
					}
				}

				// Note: Thinking validation handled at request level to avoid incompatible message structures

				if !content.is_empty() || has_tool_calls {
					messages.push(types::Message {
						role: types::Role::Assistant,
						content,
					});
				}

				// Check if this assistant has tool calls - if so, coalesce the following pattern:
				// Tool messages → optional User message into a single User message
				if has_tool_calls {
					i += 1; // Move past assistant

					// Collect tool_call_ids from the assistant to match against
					// Safe: has_tool_calls already verified tool_calls exists and is non-empty
					let tool_call_ids: std::collections::HashSet<String> = assistant_msg.tool_calls
						.as_ref()
						.map(|calls| calls.iter().map(|call| call.id.clone()).collect())
						.unwrap_or_default();

					debug!("Bedrock: Assistant at index {} has {} tool_calls", i-1, tool_call_ids.len());

					// Step 1: Collect contiguous Tool messages that match the assistant's tool_calls
					use std::collections::BTreeMap;

					let mut tool_results_by_id: BTreeMap<String, types::ToolResultBlock> = BTreeMap::new();

					// Collect any User messages that come before Tool messages (Messages API creates Assistant→User→Tool sequence)
					let mut user_content = Vec::new();
					while i < req.messages.len() && matches!(&req.messages[i], universal::RequestMessage::User(_)) {
						user_content.extend(convert_openai_message_to_bedrock_content(&req.messages[i], tool_results_meta.as_ref()));
						i += 1;
					}

					while i < req.messages.len() {
						if let universal::RequestMessage::Tool(tool_msg) = &req.messages[i] {
							if !tool_call_ids.contains(&tool_msg.tool_call_id) {
								debug!(
									"Bedrock: Tool message at index {} with id '{}' doesn't match assistant's tool_calls, stopping collection",
									i, tool_msg.tool_call_id
								);
								break;
							}

							// Build a single chunk for this tool message (text-only today)
							let chunk_text = match &tool_msg.content {
								universal::RequestToolMessageContent::Text(t) => t.clone(),
								universal::RequestToolMessageContent::Array(parts) => parts.iter()
									.map(|p| match p {
										async_openai::types::ChatCompletionRequestToolMessageContentPart::Text(tp) => tp.text.as_str(),
									})
									.collect::<Vec<_>>()
									.join("\n"),
							};

							let id = tool_msg.tool_call_id.clone();
							let status = tool_results_meta
								.as_ref()
								.and_then(|m| m.get(&id))
								.map(|is_error| if *is_error { types::ToolResultStatus::Error } else { types::ToolResultStatus::Success });

							let entry = tool_results_by_id.entry(id.clone()).or_insert_with(|| types::ToolResultBlock {
								tool_use_id: id.clone(),
								content: Vec::new(),
								status: status.clone(),
							});

							// Prefer Error if any chunk marks it as Error
							entry.status = match (entry.status.take(), status) {
								(Some(types::ToolResultStatus::Error), _) | (_, Some(types::ToolResultStatus::Error)) => {
									Some(types::ToolResultStatus::Error)
								}
								(Some(types::ToolResultStatus::Success), Some(types::ToolResultStatus::Success)) => {
									Some(types::ToolResultStatus::Success)
								}
								(s @ Some(_), None) | (None, s @ Some(_)) => s,
								(None, None) => None,
							};

							entry.content.push(ContentBlock::Text(chunk_text));
							i += 1;
						} else {
							break;
						}
					}

					// Materialize aggregated results - but we MUST have results for each tool_use!
					let mut tool_results: Vec<ContentBlock> = Vec::new();

					// Create tool_results only for tool_calls that have matching Tool messages
					for tool_call_id in &tool_call_ids {
						if let Some(result) = tool_results_by_id.remove(tool_call_id) {
							tool_results.push(ContentBlock::ToolResult(result));
						}
					}

					debug!("Bedrock: Created {} tool_results for {} tool_calls", tool_results.len(), tool_call_ids.len());

					// Step 2: User messages already collected above

					// Step 3: Create a single User message with tool_results FIRST, then user text
					let mut combined_content = tool_results;
					combined_content.extend(user_content);

					// ALWAYS create a User message after Assistant with tool_use
					// Bedrock REQUIRES this for proper sequencing
					messages.push(types::Message {
						role: types::Role::User,
						content: combined_content,
					});

					continue; // We've already advanced i appropriately
				}

				i += 1;
			},
			_ => {
				// Handle other message types (User, Function, Developer)
				let role = match &req.messages[i] {
					universal::RequestMessage::User(_) => types::Role::User,
					universal::RequestMessage::Function(_) => types::Role::User, // Map deprecated function to user
					universal::RequestMessage::Developer(_) => types::Role::User, // Map developer to user
					universal::RequestMessage::Tool(_) => {
						// Tool messages at root level need special handling
						// CRITICAL: Tool results can ONLY be created if they immediately follow
						// the Assistant message with matching tool_use blocks

						// Bedrock's strict requirement: tool_result blocks must be in the
						// IMMEDIATELY following message after tool_use blocks

						// Check if the immediately preceding message is an Assistant with tool_calls
						let can_create_tool_results = messages.last()
							.map(|last_bedrock_msg| {
								// Check if it's an Assistant with tool_use blocks
								if last_bedrock_msg.role == types::Role::Assistant {
									// Check if it has tool_use blocks
									last_bedrock_msg.content.iter().any(|block| {
										matches!(block, ContentBlock::ToolUse(_))
									})
								} else {
									false
								}
							})
							.unwrap_or(false);

						// Collect ALL contiguous Tool messages
						// If we can create tool results, get the tool_use_ids from the last assistant
						let valid_tool_ids: std::collections::HashSet<String> = if can_create_tool_results {
							// Extract tool_use_ids from the last assistant's content
							messages.last()
								.map(|msg| {
									msg.content.iter()
										.filter_map(|block| {
											if let ContentBlock::ToolUse(tu) = block {
												Some(tu.tool_use_id.clone())
											} else {
												None
											}
										})
										.collect()
								})
								.unwrap_or_default()
						} else {
							std::collections::HashSet::new()
						};

						let (aggregated_results, orphaned_tools) = aggregate_tool_results(
							&req.messages,
							&mut i,
							&valid_tool_ids,
							tool_results_meta.as_ref()
						);

						// Create User message with collected content
						let mut content = Vec::new();

						// Add proper tool_results first
						content.extend(
							aggregated_results.into_iter()
								.map(ContentBlock::ToolResult)
						);

						// Add orphaned tools as plain text
						if !orphaned_tools.is_empty() {
							content.push(ContentBlock::Text(orphaned_tools.join("\n\n")));
						}

						if !content.is_empty() {
							messages.push(types::Message {
								role: types::Role::User,
								content,
							});
						}
						continue; // Already advanced i
					},
					universal::RequestMessage::System(_) => unreachable!(), // Already handled above
					universal::RequestMessage::Assistant(_) => unreachable!(), // Already handled above
				};

				let content = convert_openai_message_to_bedrock_content(
					&req.messages[i],
					tool_results_meta.as_ref()
				);
				if !content.is_empty() {
					messages.push(types::Message { role, content });
				}
				i += 1;
			}
		}
	}

	// Build system content blocks with cache points if needed
	let system = if system_text.is_empty() {
		None
	} else {
		let mut blocks = vec![types::SystemContentBlock::Text(system_text.join("\n"))];

		// Add cache point at end of static prefix if cache plan exists
		if let Some(cache) = &req.cache {
			if cache.boundary == universal::BoundaryLocation::EndOfStaticPrefix {
				blocks.push(types::SystemContentBlock::CachePoint(types::CachePointBlock {
					cache_type: types::CachePointType::Default,
				}));
			}
		}

		Some(blocks)
	};

	// Build inference configuration from OpenAI request fields
	let inference_config = types::InferenceConfiguration {
		max_tokens: Some(universal::max_tokens(req) as i32),
		temperature: req.temperature,
		top_p: req.top_p,
		stop_sequences: req.stop.as_ref().map(|stop| match stop {
			async_openai::types::Stop::String(s) => vec![s.clone()],
			async_openai::types::Stop::StringArray(arr) => arr.clone(),
		}),
	};

	// Build guardrail configuration if specified
	let guardrail_config = if let (Some(identifier), Some(version)) =
		(&provider.guardrail_identifier, &provider.guardrail_version)
	{
		Some(types::GuardrailConfiguration {
			guardrail_identifier: identifier.to_string(),
			guardrail_version: version.to_string(),
			stream_processing_mode: None, // Default for now
			trace: Some("enabled".to_string()),
		})
	} else {
		None
	};

	// Convert tools to Bedrock format
	let tool_config = req.tools.as_ref().map(|tools| {
		let mut bedrock_tools = Vec::new();

		// Convert OpenAI tools to Bedrock ToolSpec format FIRST
		for tool in tools {
			let tool_spec = types::ToolSpecification {
				name: tool.function.name.clone(),
				description: tool.function.description.clone(),
				input_schema: Some(types::ToolInputSchema::Json(tool.function.parameters.clone().unwrap_or_default())),
			};
			bedrock_tools.push(types::Tool::ToolSpec(tool_spec));
		}

		// THEN add cache point at END of static prefix (after tool specs)
		if let Some(cache) = &req.cache {
			if cache.boundary == universal::BoundaryLocation::EndOfStaticPrefix && !bedrock_tools.is_empty() {
				bedrock_tools.push(types::Tool::CachePoint(types::CachePointBlock {
					cache_type: types::CachePointType::Default,
				}));
			}
		}


		// Coerce tool_choice when thinking+tools is enabled
		let effective_tool_choice = if req.reasoning.as_ref().is_some_and(|r| r.enabled) {
			// Bedrock: "Thinking may not be enabled when tool_choice forces tool use"
			// So we must use "auto" (or None) when thinking is enabled
			match req.tool_choice.as_ref() {
				Some(universal::ToolChoiceOption::Required) | Some(universal::ToolChoiceOption::Named(_)) => {
					debug!("Bedrock: Coercing tool_choice from forced tool use to 'auto' for thinking+tools compatibility");
					Some(universal::ToolChoiceOption::Auto)
				},
				other => {
					debug!("Bedrock: Keeping tool_choice as {:?} for thinking+tools compatibility", other);
					other.cloned()
				}
			}
		} else {
			req.tool_choice.clone()
		};

		types::ToolConfiguration {
			tools: bedrock_tools,
			tool_choice: effective_tool_choice.as_ref().and_then(|choice| {
				match choice {
					universal::ToolChoiceOption::None => {
						// OpenAI "none" -> No tool choice (omit tool_choice field entirely)
						None
					},
					universal::ToolChoiceOption::Auto => {
						Some(types::ToolChoice::Auto(types::AutoToolChoice {
							auto: serde_json::Value::Object(serde_json::Map::new()), // {}
						}))
					},
					universal::ToolChoiceOption::Required => {
						Some(types::ToolChoice::Any(types::AnyToolChoice {
							any: serde_json::Value::Object(serde_json::Map::new()), // {}
						}))
					},
					universal::ToolChoiceOption::Named(named) => {
						Some(types::ToolChoice::Tool(types::ToolChoiceSpecific {
							tool: types::ToolChoiceToolSpec {
								name: named.function.name.clone(),
							},
						}))
					},
				}
			}),
		}
	});

	debug!("Bedrock: Translation complete. Output: {} messages", messages.len());
	for (idx, msg) in messages.iter().enumerate() {
		debug!("  [{}] {:?} with {} content blocks", idx, msg.role, msg.content.len());
		for (cidx, block) in msg.content.iter().enumerate() {
			match block {
				ContentBlock::ToolUse(tu) => {
					debug!("    [{}] ToolUse: {}", cidx, tu.tool_use_id);
				},
				ContentBlock::ToolResult(tr) => {
					debug!("    [{}] ToolResult: {}", cidx, tr.tool_use_id);
				},
				ContentBlock::Text(t) => {
					debug!("    [{}] Text: {} chars", cidx, t.len());
				},
				_ => {}
			}
		}
	}

	let bedrock_request = ConverseRequest {
		model_id: model.to_string(),
		messages: Some(messages),
		system,
		inference_config: Some(inference_config),
		tool_config,
		guardrail_config,
		additional_model_request_fields,
		additional_model_response_field_paths: None,
		request_metadata: None,
		performance_config: None,
	};

	// Debug: Log the actual request JSON going to Bedrock
	if let Ok(json) = serde_json::to_string_pretty(&bedrock_request) {
		debug!("Bedrock: Sending request JSON:\n{}", json);
	}

	Ok(bedrock_request)
}

/// Extract thinking blocks from preserved Anthropic content for re-emission in Bedrock requests
/// This is required for tool follow-up requests when thinking is enabled
fn extract_thinking_blocks_for_assistant(
	req: &universal::Request,
	assistant_msg: &universal::RequestAssistantMessage,
) -> Option<Vec<ContentBlock>> {
	// Get the first tool_use_id from this assistant to match against preserved content
	let first_tool_id = assistant_msg.tool_calls
		.as_ref()?
		.first()?
		.id
		.clone();

	// Look up preserved content blocks from provider_data
	let content_blocks_by_msg = req.providers
		.as_ref()?
		.get("anthropic")?
		.get("content_blocks_by_msg")?
		.as_array()?;

	// Find the message that contains this tool_use_id
	for msg_blocks in content_blocks_by_msg {
		if let Some(blocks) = msg_blocks.as_array() {
			// Check if this message contains our tool_use_id
			let has_matching_tool = blocks.iter().any(|block| {
				block.get("type").and_then(|t| t.as_str()) == Some("tool_use") &&
				block.get("id").and_then(|id| id.as_str()) == Some(&first_tool_id)
			});

			if has_matching_tool {
				// Extract thinking blocks from this message (they should be at the beginning)
				let mut thinking_blocks = Vec::new();

				for block in blocks {
					match block.get("type").and_then(|t| t.as_str()) {
						Some("thinking") => {
							let text = block.get("thinking")
								.and_then(|t| t.as_str())
								.unwrap_or_default()
								.to_string();
							let signature = block.get("signature")
								.and_then(|s| s.as_str())
								.map(|s| s.to_string());

							thinking_blocks.push(ContentBlock::ReasoningContent(
								types::ReasoningContentBlock {
									reasoning_text: Some(types::ReasoningTextBlock {
										text,
										signature
									}),
									redacted_content: None,
								}
							));
						},
						Some("redacted_thinking") => {
							let data = block.get("data")
								.and_then(|d| d.as_str())
								.unwrap_or_default()
								.to_string();

							thinking_blocks.push(ContentBlock::ReasoningContent(
								types::ReasoningContentBlock {
									reasoning_text: None,
									redacted_content: Some(data),
								}
							));
						},
						Some("text") | Some("tool_use") => {
							// Stop once we reach non-thinking content
							break;
						},
						_ => continue,
					}
				}

				if !thinking_blocks.is_empty() {
					return Some(thinking_blocks);
				}
			}
		}
	}

	None
}



/// Convert OpenAI message content to Bedrock ContentBlocks (fallback for non-Anthropic requests)
fn convert_openai_message_to_bedrock_content(
	msg: &universal::RequestMessage,
	tool_results_meta: Option<&std::collections::HashMap<String, bool>>
) -> Vec<ContentBlock> {
	let mut content = Vec::new();

	match msg {
		universal::RequestMessage::User(user_msg) => {
			match &user_msg.content {
				universal::RequestUserMessageContent::Text(text) => {
					content.push(ContentBlock::Text(text.clone()));
				},
				universal::RequestUserMessageContent::Array(parts) => {
					for part in parts {
						match part {
							async_openai::types::ChatCompletionRequestUserMessageContentPart::Text(text_part) => {
								content.push(ContentBlock::Text(text_part.text.clone()));
							},
							async_openai::types::ChatCompletionRequestUserMessageContentPart::ImageUrl(_image_part) => {
								// TODO: Convert image URLs to Bedrock image format
								// For now, skip images
							},
							async_openai::types::ChatCompletionRequestUserMessageContentPart::InputAudio(_) => {
								// TODO: Handle audio content
								// For now, skip audio
							},
						}
					}
				}
			}
		},
		universal::RequestMessage::Assistant(assistant_msg) => {
			if let Some(content_text) = &assistant_msg.content {
				let text = match content_text {
					universal::RequestAssistantMessageContent::Text(text) => text.clone(),
					universal::RequestAssistantMessageContent::Array(parts) => {
						// Convert array of content parts to text - for now, just extract text parts
						parts.iter().map(|part| {
							match part {
								async_openai::types::ChatCompletionRequestAssistantMessageContentPart::Text(text_part) => {
									text_part.text.as_str()
								}
								async_openai::types::ChatCompletionRequestAssistantMessageContentPart::Refusal(refusal_part) => {
									refusal_part.refusal.as_str()
								}
							}
						}).collect::<Vec<_>>().join("\n")
					}
				};
				content.push(ContentBlock::Text(text));
			}
			if let Some(tool_calls) = &assistant_msg.tool_calls {
				for tool_call in tool_calls {
					content.push(ContentBlock::ToolUse(types::ToolUseBlock {
						tool_use_id: tool_call.id.clone(),
						name: tool_call.function.name.clone(),
						input: serde_json::from_str(&tool_call.function.arguments)
							.unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
					}));
				}
			}
		},
		universal::RequestMessage::Tool(tool_msg) => {
			let text = match &tool_msg.content {
				universal::RequestToolMessageContent::Text(text) => text.clone(),
				universal::RequestToolMessageContent::Array(parts) => {
					parts.iter().map(|part| {
						match part {
							async_openai::types::ChatCompletionRequestToolMessageContentPart::Text(text_part) => {
								text_part.text.as_str()
							}
						}
					}).collect::<Vec<_>>().join("\n")
				}
			};
			// Look up is_error from vendor bag to set appropriate Bedrock ToolResult.status
			let status = tool_results_meta
				.and_then(|meta| meta.get(&tool_msg.tool_call_id))
				.map(|is_error| {
					if *is_error {
						types::ToolResultStatus::Error
					} else {
						types::ToolResultStatus::Success
					}
				});

			content.push(ContentBlock::ToolResult(types::ToolResultBlock {
				tool_use_id: tool_msg.tool_call_id.clone(),
				content: vec![ContentBlock::Text(text)],
				status,
			}));
		},
		universal::RequestMessage::Function(func_msg) => {
			// Legacy function message - no reliable tool_call_id; degrade to text
			if let Some(c) = &func_msg.content {
				content.push(ContentBlock::Text(format!("[Function: {}]\n{}", func_msg.name, c)));
			}
		},
		universal::RequestMessage::Developer(dev_msg) => {
			match &dev_msg.content {
				universal::RequestDeveloperMessageContent::Text(text) => {
					content.push(ContentBlock::Text(text.clone()));
				},
				universal::RequestDeveloperMessageContent::Array(parts) => {
					for part in parts {
						content.push(ContentBlock::Text(part.text.clone()));
					}
				}
			}
		},
		universal::RequestMessage::System(_) => {
			// System messages handled separately
		}
	}

	content
}



pub(super) mod types {
	//! Complete Bedrock Converse API types from vendors/messages
	
	use serde::{Deserialize, Serialize};
	use std::collections::HashMap;

/// Bedrock Converse request structure
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConverseRequest {
	/// Required: Model ID to invoke (URI parameter in actual API)
	#[serde(skip)]
	pub model_id: String,

	/// Optional: Array of messages (max conversation length varies by model)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub messages: Option<Vec<Message>>,

	/// Optional: System prompt content blocks
	#[serde(skip_serializing_if = "Option::is_none")]
	pub system: Option<Vec<SystemContentBlock>>,

	/// Optional: Inference configuration parameters
	#[serde(skip_serializing_if = "Option::is_none")]
	pub inference_config: Option<InferenceConfiguration>,

	/// Optional: Tool configuration
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tool_config: Option<ToolConfiguration>,

	/// Optional: Guardrail configuration
	#[serde(skip_serializing_if = "Option::is_none")]
	pub guardrail_config: Option<GuardrailConfiguration>,

	/// Optional: Model-specific additional request fields
	#[serde(skip_serializing_if = "Option::is_none")]
	pub additional_model_request_fields: Option<serde_json::Value>,

	/// Optional: Response field paths to include
	#[serde(skip_serializing_if = "Option::is_none")]
	pub additional_model_response_field_paths: Option<Vec<String>>,

	/// Optional: Performance configuration
	#[serde(skip_serializing_if = "Option::is_none")]
	pub performance_config: Option<PerformanceConfiguration>,

	/// Optional: Request metadata (string key-value pairs)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub request_metadata: Option<HashMap<String, String>>,
}

/// Message structure
bedrock_struct! {
pub struct Message {
	pub role: ConversationRole,
	pub content: Vec<ContentBlock>,
}
}

/// Conversation roles
bedrock_enum! {
#[derive(PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConversationRole {
	User,
	Assistant,
}
}

// Alias for backward compatibility with existing bedrock.rs code
pub type Role = ConversationRole;

/// CRITICAL: ContentBlock is a strict UNION type - exactly one variant must be set
/// Multiple variants will cause validation errors
/// FORMAT: Tuple variants to match AWS SDK serialization exactly
bedrock_enum! {
pub enum ContentBlock {
	/// Text content block
	#[serde(rename = "text")]
	Text(String),

	/// Image content block (Claude 3 only)  
	#[serde(rename = "image")]
	Image(ImageBlock),

	/// Document content block
	#[serde(rename = "document")]
	Document(DocumentBlock),

	/// Tool use content block
	#[serde(rename = "toolUse")]
	ToolUse(ToolUseBlock),

	/// Tool result content block
	#[serde(rename = "toolResult")]
	ToolResult(ToolResultBlock),

	/// Cache point for performance optimization
	#[serde(rename = "cachePoint")]
	CachePoint(CachePointBlock),

	/// Reasoning content (for thinking mode)
	#[serde(rename = "reasoningContent")]
	ReasoningContent(ReasoningContentBlock),
}
}

/// Image content block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageBlock {
	/// Image format
	pub format: ImageFormat,

	/// Image source
	pub source: ImageSource,
}

/// Supported image formats
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageFormat {
	Png,
	Jpeg,
	Gif,
	Webp,
}

/// Image source types
bedrock_enum! {
#[serde(untagged)]
pub enum ImageSource {
	/// Base64-encoded image data
	Bytes {
		#[serde(rename = "bytes")]
		data: String, // Base64 encoded
	},

	/// S3 location
	S3Location {
		#[serde(rename = "s3Location")]
		s3_location: S3Location,
	},
}
}

/// S3 location structure
bedrock_struct! {
#[serde(rename_all = "camelCase")]
pub struct S3Location {
	pub uri: String,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub bucket_owner: Option<String>,
}
}

/// Document content block  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentBlock {
	/// Document name (required, 1-200 chars)
	pub name: String,

	/// Document source (required)
	pub source: DocumentSource,

	/// Document format (optional)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub format: Option<String>,

	/// Citations configuration (optional)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub citations: Option<CitationsConfig>,

	/// Context information (optional)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub context: Option<String>,
}

/// Citations configuration for documents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitationsConfig {
	/// Whether citations are enabled
	pub enabled: bool,
}

/// Supported document formats
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DocumentFormat {
	Pdf,
	Csv,
	Doc,
	Docx,
	Xls,
	Xlsx,
	Html,
	Txt,
	Md,
}

/// Document source types  
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DocumentSource {
	/// Base64-encoded document data
	Bytes {
		#[serde(rename = "bytes")]
		data: String,
	},

	/// S3 location
	S3Location {
		#[serde(rename = "s3Location")]
		s3_location: S3Location,
	},
}

/// Tool use content block
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolUseBlock {
	/// Tool use identifier
	pub tool_use_id: String,

	/// Tool name
	pub name: String,

	/// Tool input (JSON object)
	pub input: serde_json::Value,
}

/// Tool result content block
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResultBlock {
	/// Tool use ID this result corresponds to
	pub tool_use_id: String,

	/// Result content blocks - Must use ContentBlock to match Bedrock API
	pub content: Vec<ContentBlock>,

	/// Result status (Claude 3 only)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub status: Option<ToolResultStatus>,
}

/// Tool result status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolResultStatus {
	Success,
	Error,
}

/// Cache point for performance optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachePointBlock {
	#[serde(rename = "type")]
	pub cache_type: CachePointType,
}

/// Cache point types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CachePointType {
	Default,
}

/// Reasoning content (chain of thought) - UNION type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReasoningContentBlock {
	/// Reasoning text with optional signature
	#[serde(skip_serializing_if = "Option::is_none")]
	pub reasoning_text: Option<ReasoningTextBlock>,

	/// Redacted content (base64-encoded)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub redacted_content: Option<String>,
}

/// Reasoning text block with signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningTextBlock {
	pub text: String,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub signature: Option<String>,
}

/// System content blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemContentBlock {
	/// Text system content
	#[serde(rename = "text")]
	Text(String),

	/// Cache point in system
	#[serde(rename = "cachePoint")]
	CachePoint(CachePointBlock),
}

/// Inference configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InferenceConfiguration {
	/// Maximum tokens to generate (minimum 1)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub max_tokens: Option<i32>,

	/// Stop sequences
	#[serde(skip_serializing_if = "Option::is_none")]
	pub stop_sequences: Option<Vec<String>>,

	/// Temperature (0.0 to 1.0)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub temperature: Option<f32>,

	/// Top-p nucleus sampling (0.0 to 1.0)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub top_p: Option<f32>,
}

/// Tool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolConfiguration {
	/// Array of tools
	pub tools: Vec<Tool>,

	/// Tool choice configuration
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tool_choice: Option<ToolChoice>,
}

/// Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Tool {
	/// Cache point
	#[serde(rename = "cachePoint")]
	CachePoint(CachePointBlock),

	/// Tool specification
	#[serde(rename = "toolSpec")]
	ToolSpec(ToolSpecification),
}

/// Tool specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolSpecification {
	/// Tool name
	pub name: String,

	/// Tool description
	#[serde(skip_serializing_if = "Option::is_none")]
	pub description: Option<String>,

	/// Input schema
	#[serde(skip_serializing_if = "Option::is_none")]
	pub input_schema: Option<ToolInputSchema>,
}

/// Tool input schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolInputSchema {
	/// JSON schema
	#[serde(rename = "json")]
	Json(serde_json::Value),
}

/// Tool choice options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolChoice {
	/// Model decides (default)
	Auto(AutoToolChoice),

	/// Must use any tool  
	Any(AnyToolChoice),

	/// Must use specific tool (Claude 3 only)
	Tool(ToolChoiceSpecific),
}

/// Auto tool choice (Bedrock format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoToolChoice {
	pub auto: serde_json::Value, // Empty object {}
}

/// Any tool choice (Bedrock format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyToolChoice {
	pub any: serde_json::Value, // Empty object {}
}

/// Specific tool choice (Bedrock format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolChoiceSpecific {
	pub tool: ToolChoiceToolSpec,
}

/// Tool specification for specific tool choice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolChoiceToolSpec {
	pub name: String,
}

/// Guardrail configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardrailConfiguration {
	/// Guardrail identifier
	pub guardrail_identifier: String,

	/// Guardrail version
	pub guardrail_version: String,

	/// Stream processing mode (required by AWS)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub stream_processing_mode: Option<String>,

	/// Enable trace output (string, not enum)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub trace: Option<String>,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerformanceConfiguration {
	/// Latency optimization mode
	#[serde(skip_serializing_if = "Option::is_none")]
	pub latency: Option<LatencyMode>,
}

/// Latency optimization modes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LatencyMode {
	Standard,
	Optimized,
}

/// Converse response structure
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConverseResponse {
	/// Response output
	#[serde(skip_serializing_if = "Option::is_none")]
	pub output: Option<ConverseOutput>,

	/// Stop reason
	#[serde(skip_serializing_if = "Option::is_none")]
	pub stop_reason: Option<StopReason>,

	/// Token usage
	#[serde(skip_serializing_if = "Option::is_none")]
	pub usage: Option<TokenUsage>,

	/// Request metrics
	#[serde(skip_serializing_if = "Option::is_none")]
	pub metrics: Option<ConverseMetrics>,

	/// Error message (if this is actually an error response in success format)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub message: Option<String>,

	/// Additional model response fields
	#[serde(skip_serializing_if = "Option::is_none")]
	pub additional_model_response_fields: Option<serde_json::Value>,

	/// Performance configuration
	#[serde(skip_serializing_if = "Option::is_none")]
	pub performance_config: Option<PerformanceConfiguration>,

	/// Trace information
	#[serde(skip_serializing_if = "Option::is_none")]
	pub trace: Option<ConverseTrace>,
}

/// Response output types
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ConverseOutput {
	/// Message output with nested message field
	Message { message: Message },
}

/// Stop reasons
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
	EndTurn,
	ToolUse,
	MaxTokens,
	StopSequence,
	GuardrailIntervened,
	ContentFiltered,
}

/// Token usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenUsage {
	pub input_tokens: u32,
	pub output_tokens: u32,
	pub total_tokens: u32,

	/// Cache-specific token counts
	#[serde(skip_serializing_if = "Option::is_none")]
	pub cache_read_input_tokens: Option<u32>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub cache_write_input_tokens: Option<u32>,

	/// Additional fields that may be present in Bedrock responses
	#[serde(skip_serializing_if = "Option::is_none")]
	pub cache_read_input_token_count: Option<u32>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub cache_write_input_token_count: Option<u32>,

	/// Server-side tool usage (arbitrary JSON object)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub server_tool_usage: Option<serde_json::Value>,
}

/// Request metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConverseMetrics {
	/// Latency in milliseconds
	pub latency_ms: u64,
}

/// Trace information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConverseTrace {
	/// Guardrail trace data
	#[serde(skip_serializing_if = "Option::is_none")]
	pub guardrail: Option<serde_json::Value>,
}

/// ConverseStream output event types
#[derive(Debug, Clone)]
pub enum ConverseStreamOutput {
	MessageStart(MessageStartEvent),
	ContentBlockStart(ContentBlockStartEvent),
	ContentBlockDelta(ContentBlockDeltaEvent),
	ContentBlockStop(ContentBlockStopEvent),
	MessageStop(MessageStopEvent),
	Metadata(ConverseStreamMetadataEvent),

	// Error events
	InternalServerException(StreamErrorEvent),
	ModelStreamErrorException(StreamErrorEvent),
	ServiceUnavailableException(StreamErrorEvent),
	ThrottlingException(StreamErrorEvent),
	ValidationException(StreamErrorEvent),
	ModelTimeoutException(StreamErrorEvent),
}

impl ConverseStreamOutput {
	/// Deserialize from AWS event-stream message
	pub fn deserialize(message: aws_event_stream_parser::Message) -> Result<Self, crate::llm::AIError> {
		// Extract event type from headers
		let event_type = message
			.headers
			.headers
			.iter()
			.find(|h| h.key.as_str() == ":event-type")
			.and_then(|v| match &v.value {
				aws_event_stream_parser::HeaderValue::String(s) => Some(s.as_str()),
				_ => None,
			})
			.ok_or_else(|| crate::llm::AIError::MissingField(":event-type header".into()))?;

		// Parse body based on event type
		match event_type {
			"messageStart" => Ok(ConverseStreamOutput::MessageStart(serde_json::from_slice(
				&message.body,
			).map_err(crate::llm::AIError::ResponseParsing)?)),
			"contentBlockStart" => Ok(ConverseStreamOutput::ContentBlockStart(
				serde_json::from_slice(&message.body).map_err(crate::llm::AIError::ResponseParsing)?,
			)),
			"contentBlockDelta" => Ok(ConverseStreamOutput::ContentBlockDelta(
				serde_json::from_slice(&message.body).map_err(crate::llm::AIError::ResponseParsing)?,
			)),
			"contentBlockStop" => Ok(ConverseStreamOutput::ContentBlockStop(
				serde_json::from_slice(&message.body).map_err(crate::llm::AIError::ResponseParsing)?,
			)),
			"messageStop" => Ok(ConverseStreamOutput::MessageStop(serde_json::from_slice(
				&message.body,
			).map_err(crate::llm::AIError::ResponseParsing)?)),
			"metadata" => Ok(ConverseStreamOutput::Metadata(serde_json::from_slice(
				&message.body,
			).map_err(crate::llm::AIError::ResponseParsing)?)),

			// Error events
			"internalServerException" => Ok(ConverseStreamOutput::InternalServerException(
				serde_json::from_slice(&message.body).map_err(crate::llm::AIError::ResponseParsing)?,
			)),
			"modelStreamErrorException" => Ok(ConverseStreamOutput::ModelStreamErrorException(
				serde_json::from_slice(&message.body).map_err(crate::llm::AIError::ResponseParsing)?,
			)),
			"serviceUnavailableException" => Ok(ConverseStreamOutput::ServiceUnavailableException(
				serde_json::from_slice(&message.body).map_err(crate::llm::AIError::ResponseParsing)?,
			)),
			"throttlingException" => Ok(ConverseStreamOutput::ThrottlingException(
				serde_json::from_slice(&message.body).map_err(crate::llm::AIError::ResponseParsing)?,
			)),
			"validationException" => Ok(ConverseStreamOutput::ValidationException(
				serde_json::from_slice(&message.body).map_err(crate::llm::AIError::ResponseParsing)?,
			)),
			"modelTimeoutException" => Ok(ConverseStreamOutput::ModelTimeoutException(
				serde_json::from_slice(&message.body).map_err(crate::llm::AIError::ResponseParsing)?,
			)),

			_unknown => Err(crate::llm::AIError::UnsupportedContent),
		}
	}
}

/// Message start event
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageStartEvent {
	pub role: ConversationRole,
}

/// Content block start event
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentBlockStartEvent {
	pub content_block_index: usize,
	pub start: ContentBlockStart,
}

/// Content block start types
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ContentBlockStart {
	ToolUse {
		#[serde(rename = "toolUse")]
		tool_use: ToolUseBlockStart,
	},
	Text {
		text: String,
	},
	Reasoning {
		reasoning: String,
	},
}

/// Tool use block start
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolUseBlockStart {
	pub tool_use_id: String,
	pub name: String,
}

/// Content block delta event
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentBlockDeltaEvent {
	pub content_block_index: usize,
	pub delta: ContentBlockDelta,
}

/// Content block delta types
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ContentBlockDelta {
	/// Text content delta - matches {"text": "content"}
	Text { text: String },

	/// Tool use input delta - matches {"toolUse": {"input": "..."}}
	ToolUse {
		#[serde(rename = "toolUse")]
		tool_use: ToolUseBlockDelta,
	},

	/// Reasoning content delta - matches {"reasoningContent": {"text": "..."}}
	ReasoningContent {
		#[serde(rename = "reasoningContent")]
		reasoning_content: ReasoningContentBlockDelta,
	},

	/// Citations delta
	Citation(CitationsDelta),
}

/// Tool use block delta
#[derive(Debug, Clone, Deserialize)]
pub struct ToolUseBlockDelta {
	/// Incremental JSON input string
	pub input: String,
}

/// Reasoning content delta - UNION type (exactly one variant)
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ReasoningContentBlockDelta {
	/// Text reasoning delta - matches {"text": "content"} format from Bedrock
	Text { text: String },
}

/// Citations delta with location tracking
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CitationsDelta {
	/// Citation location information
	#[serde(skip_serializing_if = "Option::is_none")]
	pub location: Option<CitationLocation>,

	/// Source content fragments
	#[serde(skip_serializing_if = "Option::is_none")]
	pub source_content: Option<Vec<CitationSourceContentDelta>>,

	/// Citation title
	#[serde(skip_serializing_if = "Option::is_none")]
	pub title: Option<String>,

	/// Legacy citations array (backward compatibility)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub citations: Option<Vec<Citation>>,
}

/// Citation location for incremental building
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CitationLocation {
	/// Start position
	pub start: usize,

	/// End position
	pub end: usize,

	/// Location type (page, character, block, etc.)
	pub location_type: String,
}

/// Citation source content delta
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CitationSourceContentDelta {
	/// Content fragment
	pub content: String,

	/// Fragment position
	pub position: usize,
}

/// Citation structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Citation {
	pub source: String,
	pub content: String,
}

/// Content block stop event
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentBlockStopEvent {
	pub content_block_index: usize,
}

/// Message stop event
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageStopEvent {
	pub stop_reason: StopReason,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub additional_model_response_fields: Option<serde_json::Value>,
}

/// Stream metadata event
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConverseStreamMetadataEvent {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub usage: Option<TokenUsage>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub metrics: Option<ConverseMetrics>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub performance_config: Option<PerformanceConfiguration>,
}

/// Bedrock error response
#[derive(Debug, Clone, Deserialize)]
pub struct ConverseErrorResponse {
	/// Error message
	pub message: String,

}

/// Stream error event structure
#[derive(Debug, Clone, Deserialize)]
pub struct StreamErrorEvent {
	pub message: String,
}

impl ConverseRequest {
	/// Create new request with model ID
	pub fn new(model_id: String) -> Self {
		Self {
			model_id,
			messages: None,
			system: None,
			inference_config: None,
			tool_config: None,
			guardrail_config: None,
			additional_model_request_fields: None,
			additional_model_response_field_paths: None,
			performance_config: None,
			request_metadata: None,
		}
	}

	/// Add messages
	pub fn with_messages(mut self, messages: Vec<Message>) -> Self {
		self.messages = Some(messages);
		self
	}

	/// Add system prompt
	pub fn with_system(mut self, system: Vec<SystemContentBlock>) -> Self {
		self.system = Some(system);
		self
	}

	/// Add inference config
	pub fn with_inference_config(mut self, config: InferenceConfiguration) -> Self {
		self.inference_config = Some(config);
		self
	}

	/// Add tool configuration
	pub fn with_tools(mut self, tools: Vec<Tool>, tool_choice: Option<ToolChoice>) -> Self {
		self.tool_config = Some(ToolConfiguration { tools, tool_choice });
		self
	}
}

impl Message {
	/// Create user message with text
	pub fn user_text(text: String) -> Self {
		Self {
			role: ConversationRole::User,
			content: vec![ContentBlock::Text(text)],
		}
	}

	/// Create assistant message with text
	pub fn assistant_text(text: String) -> Self {
		Self {
			role: ConversationRole::Assistant,
			content: vec![ContentBlock::Text(text)],
		}
	}

	/// Create user message with tool result
	pub fn user_tool_result(
		tool_use_id: String,
		content: Vec<ContentBlock>,
		status: Option<ToolResultStatus>,
	) -> Self {
		Self {
			role: ConversationRole::User,
			content: vec![ContentBlock::ToolResult(ToolResultBlock {
				tool_use_id,
				content,
				status,
			})],
		}
	}
}

impl InferenceConfiguration {
	/// Create basic inference config
	pub fn new(max_tokens: i32) -> Self {
		Self {
			max_tokens: Some(max_tokens),
			stop_sequences: None,
			temperature: None,
			top_p: None,
		}
	}
}

} // end types module

/// Bedrock → Anthropic Messages API streaming conversion
pub mod streaming {
	use std::collections::{HashMap, VecDeque};
	use std::pin::Pin;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::task::{Context, Poll, ready};
	use std::time::Instant;

	use bytes::Bytes;
	use pin_project_lite::pin_project;
	use tokio_util::codec::Decoder;
	use tracing::debug;

	use aws_event_stream_parser::EventStreamCodec;

	use crate::http::Body;
	use crate::llm::bedrock::types::{ConverseStreamOutput, ContentBlockDelta};
	use crate::llm::{AIError, LLMResponse};
	use crate::telemetry::log::AsyncLog;
	use crate::store::LLMResponsePolicies;

	use super::{BedrockStreamError, reasons};

	/// Maximum size for accumulated tool JSON input (2MB - matches standard payload limits in codebase)
	const MAX_TOOL_JSON_SIZE: usize = 2_097_152;

	/// Global memory limit for all streaming buffers to prevent DoS attacks
	const GLOBAL_BUFFER_LIMIT: usize = 50_000_000; // 50MB total across all streams

	/// Global counter for memory usage across all streaming operations
	static GLOBAL_BUFFER_USAGE: AtomicUsize = AtomicUsize::new(0);

	/// Anthropic Messages API streaming event types
	#[derive(Debug, Clone, serde::Serialize)]
	#[serde(tag = "type")]
	pub enum StreamEvent {
		#[serde(rename = "message_start")]
		MessageStart { message: MessagesResponse },
		#[serde(rename = "content_block_start")]
		ContentBlockStart {
			index: usize,
			content_block: ResponseContentBlock,
		},
		#[serde(rename = "ping")]
		Ping,
		#[serde(rename = "content_block_delta")]
		ContentBlockDelta { index: usize, delta: ContentDelta },
		#[serde(rename = "content_block_stop")]
		ContentBlockStop { index: usize },
		#[serde(rename = "message_delta")]
		MessageDelta { delta: MessageDelta },
		#[serde(rename = "message_stop")]
		MessageStop,
		#[serde(rename = "error")]
		Error { error: ErrorResponse },
	}

	/// Content delta types for streaming updates
	#[derive(Debug, Clone, serde::Serialize)]
	#[serde(tag = "type")]
	pub enum ContentDelta {
		#[serde(rename = "text_delta")]
		TextDelta { text: String },
		#[serde(rename = "input_json_delta")]
		InputJsonDelta { partial_json: String },
		#[serde(rename = "thinking_delta")]
		ThinkingDelta { thinking: String },
	}

	/// Message delta for usage and stop information
	#[derive(Debug, Clone, serde::Serialize)]
	pub struct MessageDelta {
		pub stop_reason: Option<String>,
		pub stop_sequence: Option<String>,
		pub usage: Option<Usage>,
	}

	/// Response content blocks
	#[derive(Debug, Clone, serde::Serialize)]
	#[serde(tag = "type")]
	pub enum ResponseContentBlock {
		#[serde(rename = "text")]
		Text(ResponseTextBlock),
		#[serde(rename = "tool_use")]
		ToolUse(ResponseToolUseBlock),
		#[serde(rename = "thinking")]
		Thinking(ResponseThinkingBlock),
		#[serde(rename = "redacted_thinking")]
		RedactedThinking(ResponseRedactedThinkingBlock),
	}

	#[derive(Debug, Clone, serde::Serialize)]
	pub struct ResponseTextBlock {
		pub text: String,
		pub citations: Option<serde_json::Value>,
	}

	#[derive(Debug, Clone, serde::Serialize)]
	pub struct ResponseToolUseBlock {
		pub id: String,
		pub name: String,
		pub input: serde_json::Value,
	}

	#[derive(Debug, Clone, serde::Serialize)]
	pub struct ResponseThinkingBlock {
		pub thinking: String,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub signature: Option<String>,
	}

	#[derive(Debug, Clone, serde::Serialize)]
	pub struct ResponseRedactedThinkingBlock {
		pub data: String,
	}

	/// Messages API response structure for message_start events
	#[derive(Debug, Clone, serde::Serialize)]
	pub struct MessagesResponse {
		pub id: String,
		#[serde(rename = "type")]
		pub r#type: String,
		pub role: String,
		pub content: Vec<ResponseContentBlock>,
		pub model: String,
		pub stop_reason: Option<String>,
		pub stop_sequence: Option<String>,
		pub usage: Usage,
	}

	/// Usage information
	#[derive(Debug, Clone, serde::Serialize)]
	pub struct Usage {
		pub input_tokens: u32,
		pub output_tokens: u32,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub cache_creation_input_tokens: Option<u32>,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub cache_read_input_tokens: Option<u32>,
	}

	/// Error response structure
	#[derive(Debug, Clone, serde::Serialize)]
	pub struct ErrorResponse {
		pub error_type: String,
		pub message: String,
	}

	/// Stream event processor that converts Bedrock events to Anthropic SSE format
	pub struct BedrockStreamProcessor {
		/// Current message ID (generated since Bedrock doesn't provide one)
		message_id: String,

		/// Current model name
		model: String,

		/// Buffer for accumulating tool input JSON strings by content block index
		tool_json_buffers: HashMap<usize, String>,

		/// Track content block metadata for correlation
		content_block_metadata: HashMap<usize, ContentBlockMetadata>,

		/// Whether we've seen the first token (for timing metrics)
		seen_first_token: bool,

		/// Whether we've processed a MessageStop event (to avoid duplicate message_stop)
		message_stopped: bool,

		/// Accumulated usage information
		pub current_usage: Option<Usage>,

	}

	/// Metadata for tracking content blocks during streaming
	#[derive(Debug, Clone)]
	struct ContentBlockMetadata {
		pub block_type: ContentBlockType,
	}

	/// Types of content blocks we're tracking
	#[derive(Debug, Clone, PartialEq)]
	enum ContentBlockType {
		Text,
		ToolUse,
		Reasoning,
	}

	impl BedrockStreamProcessor {
		/// Create a new stream processor
		pub fn new(message_id: String, model: String) -> Self {
			Self {
				message_id,
				model,
				tool_json_buffers: HashMap::new(),
				content_block_metadata: HashMap::new(),
				seen_first_token: false,
				message_stopped: false,
				current_usage: None,
			}
		}

		/// Process a Bedrock stream event and convert to Anthropic events
		/// Returns Vec because some Bedrock events may produce multiple Anthropic events
		pub fn process_event(
			&mut self,
			bedrock_event: ConverseStreamOutput,
			log: &AsyncLog<LLMResponse>,
		) -> Result<Vec<StreamEvent>, AIError> {
			let mut events = Vec::new();

			match bedrock_event {
				ConverseStreamOutput::MessageStart(start_event) => {
					let event = self.handle_message_start(start_event)?;
					events.push(event);
				},

				ConverseStreamOutput::ContentBlockStart(start_event) => {
					let event = self.handle_content_block_start(start_event)?;
					events.push(event);
				},

				ConverseStreamOutput::ContentBlockDelta(delta_event) => {
					let delta_events = self.handle_content_block_delta(delta_event, log)?;
					events.extend(delta_events);
				},

				ConverseStreamOutput::ContentBlockStop(stop_event) => {
					if let Some(event) = self.handle_content_block_stop(stop_event)? {
						events.push(event);
					}
				},

				ConverseStreamOutput::MessageStop(stop_event) => {
					let stop_events = self.handle_message_stop(stop_event)?;
					events.extend(stop_events);
				},

				ConverseStreamOutput::Metadata(metadata_event) => {
					// debug!("Bedrock: Raw Metadata event: {:?}", metadata_event);
					if let Some(event) = self.handle_metadata(metadata_event)? {
						events.push(event);
					}
				},

				// Error handling - map streaming errors using centralized handling
				ConverseStreamOutput::InternalServerException(_) => {
					events.push(StreamEvent::Error {
						error: BedrockStreamError::InternalServer.to_anthropic_error(),
					});
				},
				ConverseStreamOutput::ModelStreamErrorException(_) => {
					events.push(StreamEvent::Error {
						error: BedrockStreamError::ModelStreamError.to_anthropic_error(),
					});
				},
				ConverseStreamOutput::ServiceUnavailableException(_) => {
					events.push(StreamEvent::Error {
						error: BedrockStreamError::ServiceUnavailable.to_anthropic_error(),
					});
				},
				ConverseStreamOutput::ThrottlingException(_) => {
					events.push(StreamEvent::Error {
						error: BedrockStreamError::Throttling.to_anthropic_error(),
					});
				},
				ConverseStreamOutput::ValidationException(_) => {
					events.push(StreamEvent::Error {
						error: BedrockStreamError::Validation.to_anthropic_error(),
					});
				},
				ConverseStreamOutput::ModelTimeoutException(_) => {
					events.push(StreamEvent::Error {
						error: BedrockStreamError::ModelTimeout.to_anthropic_error(),
					});
				},
			}

			Ok(events)
		}

		/// Handle Bedrock MessageStart → Anthropic message_start
		fn handle_message_start(
			&mut self,
			_start_event: crate::llm::bedrock::types::MessageStartEvent,
		) -> Result<StreamEvent, AIError> {
			// Create initial message with empty content for message_start
			let message = MessagesResponse {
				id: self.message_id.clone(),
				r#type: "message".to_string(),
				role: "assistant".to_string(),
				content: Vec::new(),
				model: self.model.clone(),
				stop_reason: None,
				stop_sequence: None,
				usage: Usage {
					input_tokens: 0,  // TODO: Should be actual input token count
					output_tokens: 0,
					cache_creation_input_tokens: None,
					cache_read_input_tokens: None,
				},
			};

			Ok(StreamEvent::MessageStart { message })
		}

		/// Handle Bedrock ContentBlockStart → Anthropic content_block_start
		fn handle_content_block_start(
			&mut self,
			start_event: crate::llm::bedrock::types::ContentBlockStartEvent,
		) -> Result<StreamEvent, AIError> {
			let index = start_event.content_block_index as usize;

			let (content_block, metadata) = match start_event.start {
				crate::llm::bedrock::types::ContentBlockStart::ToolUse { tool_use } => {
					// debug!("Bedrock: Received ToolUse ContentBlockStart event: {:?}", tool_use);
					let metadata = ContentBlockMetadata {
						block_type: ContentBlockType::ToolUse,
					};

					let content_block = ResponseContentBlock::ToolUse(ResponseToolUseBlock {
						id: tool_use.tool_use_id,
						name: tool_use.name,
						input: serde_json::Value::Object(serde_json::Map::new()), // Empty initially
					});

					(content_block, metadata)
				},

				crate::llm::bedrock::types::ContentBlockStart::Text { text: _ } => {
					// debug!("Bedrock: Received Text ContentBlockStart event: {:?}", text);
					let metadata = ContentBlockMetadata {
						block_type: ContentBlockType::Text,
					};

					let content_block = ResponseContentBlock::Text(ResponseTextBlock {
						text: String::new(),
						citations: None,
					});

					(content_block, metadata)
				},

				crate::llm::bedrock::types::ContentBlockStart::Reasoning { reasoning: _ } => {
					// debug!("Bedrock: Received reasoning ContentBlockStart event: {:?}", reasoning);
					let metadata = ContentBlockMetadata {
						block_type: ContentBlockType::Reasoning,
					};

					let content_block = ResponseContentBlock::Thinking(ResponseThinkingBlock {
						thinking: String::new(),
						signature: None,
					});

					(content_block, metadata)
				},
			};

			// Store metadata for delta processing
			self.content_block_metadata.insert(index, metadata);

			Ok(StreamEvent::ContentBlockStart {
				index,
				content_block,
			})
		}

		/// Handle Bedrock ContentBlockDelta → Anthropic content_block_delta
		fn handle_content_block_delta(
			&mut self,
			delta_event: crate::llm::bedrock::types::ContentBlockDeltaEvent,
			log: &AsyncLog<LLMResponse>,
		) -> Result<Vec<StreamEvent>, AIError> {
			let index = delta_event.content_block_index as usize;

			// Mark first token seen for timing
			if !self.seen_first_token {
				self.seen_first_token = true;
				log.non_atomic_mutate(|r| {
					r.first_token = Some(Instant::now());
				});
			}

			let events = match delta_event.delta {
				ContentBlockDelta::Text { text } => {
					let mut events = Vec::new();

					// Check if we need to emit a content_block_start for this text block
					if !self.content_block_metadata.contains_key(&index) {
						// Store metadata for this text block
						let metadata = ContentBlockMetadata {
							block_type: ContentBlockType::Text,
						};
						self.content_block_metadata.insert(index, metadata);

						// Emit content_block_start event for text block
						events.push(StreamEvent::ContentBlockStart {
							index,
							content_block: ResponseContentBlock::Text(ResponseTextBlock {
								text: String::new(),
								citations: None,
							}),
						});
					}

					// Estimate incremental token usage (~4 chars per token)
					let estimated_new_tokens = (text.len() / 4).max(1) as u32;

					// Update running usage estimate
					let should_emit_usage = if let Some(current) = &mut self.current_usage {
						let old_tokens = current.output_tokens;
						current.output_tokens += estimated_new_tokens;
						// Emit usage every ~10 tokens to reduce event spam
						current.output_tokens / 10 > old_tokens / 10
					} else {
						self.current_usage = Some(Usage {
							input_tokens: 0, // Will be corrected by final metadata event
							output_tokens: estimated_new_tokens,
							cache_creation_input_tokens: None,
							cache_read_input_tokens: None,
						});
						false // Don't emit on first delta
					};

					events.push(StreamEvent::ContentBlockDelta {
						index,
						delta: ContentDelta::TextDelta { text }
					});

					// Emit periodic usage updates
					if should_emit_usage {
						if let Some(usage) = &self.current_usage {
							events.push(StreamEvent::MessageDelta {
								delta: MessageDelta {
									stop_reason: None,
									stop_sequence: None,
									usage: Some(usage.clone()),
								}
							});
						}
					}

					events
				},

				ContentBlockDelta::ToolUse { tool_use } => {
					// Accumulate partial JSON for tool inputs with bounds checking
					let json_buffer = self.tool_json_buffers.entry(index).or_default();

					// Check both per-buffer and global memory limits to prevent DoS attacks
					let new_size = json_buffer.len() + tool_use.input.len();
					let current_global_usage = GLOBAL_BUFFER_USAGE.load(Ordering::Relaxed);

					if new_size > MAX_TOOL_JSON_SIZE ||
					   current_global_usage + tool_use.input.len() > GLOBAL_BUFFER_LIMIT {
						// Clean up buffer and return error
						if let Some(removed_buffer) = self.tool_json_buffers.remove(&index) {
							// Decrement global counter for removed buffer
							GLOBAL_BUFFER_USAGE.fetch_sub(removed_buffer.len(), Ordering::Relaxed);
						}
						return Err(crate::llm::AIError::RequestTooLarge);
					}

					// Update global counter for new data
					GLOBAL_BUFFER_USAGE.fetch_add(tool_use.input.len(), Ordering::Relaxed);

					json_buffer.push_str(&tool_use.input);

					vec![StreamEvent::ContentBlockDelta {
						index,
						delta: ContentDelta::InputJsonDelta {
							partial_json: tool_use.input,
						}
					}]
				},

				ContentBlockDelta::ReasoningContent { reasoning_content } => {
					// debug!("Bedrock: Received reasoning ContentBlockDelta event: {:?}", reasoning_content);

					let mut events = Vec::new();

					// If we haven't started a thinking block for this index, synthesize one
					if !self.content_block_metadata.contains_key(&index) {
						let metadata = ContentBlockMetadata {
							block_type: ContentBlockType::Reasoning,
						};
						self.content_block_metadata.insert(index, metadata);

						events.push(StreamEvent::ContentBlockStart {
							index,
							content_block: ResponseContentBlock::Thinking(ResponseThinkingBlock {
								thinking: String::new(),
								signature: None,
							}),
						});
					}

					// Map Bedrock reasoning delta → Anthropic thinking_delta
					let thinking = match reasoning_content {
						crate::llm::bedrock::types::ReasoningContentBlockDelta::Text { text } => text,
					};

					// Estimate incremental token usage for thinking content (~4 chars per token)
					let estimated_new_tokens = (thinking.len() / 4).max(1) as u32;

					// Update running usage estimate
					let should_emit_usage = if let Some(current) = &mut self.current_usage {
						let old_tokens = current.output_tokens;
						current.output_tokens += estimated_new_tokens;
						// Emit usage every ~10 tokens to reduce event spam
						current.output_tokens / 10 > old_tokens / 10
					} else {
						self.current_usage = Some(Usage {
							input_tokens: 0, // Will be corrected by final metadata event
							output_tokens: estimated_new_tokens,
							cache_creation_input_tokens: None,
							cache_read_input_tokens: None,
						});
						false // Don't emit on first delta
					};

					// debug!("Bedrock: Emitting ThinkingDelta with {} chars", thinking.len());
					events.push(StreamEvent::ContentBlockDelta {
						index,
						delta: ContentDelta::ThinkingDelta { thinking }
					});

					// Emit periodic usage updates for thinking content too
					if should_emit_usage {
						if let Some(usage) = &self.current_usage {
							events.push(StreamEvent::MessageDelta {
								delta: MessageDelta {
									stop_reason: None,
									stop_sequence: None,
									usage: Some(usage.clone()),
								}
							});
						}
					}

					events
				},

				ContentBlockDelta::Citation(_citation_delta) => {
					// debug!("Bedrock: Received Citation delta: {:?}", citation_delta);
					// Citations are typically accumulated and attached to text blocks
					// For now, we'll skip them in the streaming interface
					vec![]
				},
			};

			Ok(events)
		}

		/// Handle Bedrock ContentBlockStop → Anthropic content_block_stop
		fn handle_content_block_stop(
			&mut self,
			stop_event: crate::llm::bedrock::types::ContentBlockStopEvent,
		) -> Result<Option<StreamEvent>, AIError> {
			let index = stop_event.content_block_index as usize;

			// Only emit ContentBlockStop if we previously emitted ContentBlockStart for this index
			// This prevents invalid event sequences that break clients
			let should_emit = self.content_block_metadata.contains_key(&index);

			// Clean up tool JSON buffer if present
			if let Some(metadata) = self.content_block_metadata.get(&index)
				&& metadata.block_type == ContentBlockType::ToolUse
				&& let Some(json_buffer) = self.tool_json_buffers.remove(&index)
			{
				// Update global counter when removing buffer
				GLOBAL_BUFFER_USAGE.fetch_sub(json_buffer.len(), Ordering::Relaxed);

				// debug!("assembled tool input JSON (len={})", json_buffer.len());
			}

			// Clean up metadata
			self.content_block_metadata.remove(&index);

			// Only emit stop event if we started this block
			if should_emit {
				Ok(Some(StreamEvent::ContentBlockStop { index }))
			} else {
				debug!("Bedrock: Skipping ContentBlockStop for index {} (no matching ContentBlockStart)", index);
				Ok(None)
			}
		}

		/// Handle Bedrock MessageStop → Anthropic message_stop
		fn handle_message_stop(
			&mut self,
			stop_event: crate::llm::bedrock::types::MessageStopEvent,
		) -> Result<Vec<StreamEvent>, AIError> {
			// Mark that we've processed a MessageStop event
			self.message_stopped = true;
			let mut events = Vec::new();

			// First, emit ContentBlockStop for any open blocks
			// Some Bedrock streams won't send explicit stops for all blocks
			let open_indices: Vec<usize> = self.content_block_metadata.keys().cloned().collect();
			for index in open_indices {
				debug!("Bedrock: Closing open content block at index {} during message stop", index);
				events.push(StreamEvent::ContentBlockStop { index });
				self.content_block_metadata.remove(&index);
			}

			// Convert stop reason
			let stop_reason = reasons::to_anthropic(&stop_event.stop_reason);

			let delta = MessageDelta {
				stop_reason: Some(stop_reason.to_string()),
				stop_sequence: None, // Bedrock doesn't provide matched sequence details
				usage: self.current_usage.clone(),
			};

			events.push(StreamEvent::MessageDelta { delta });
			events.push(StreamEvent::MessageStop);

			Ok(events)
		}

		/// Handle Bedrock Metadata events
		fn handle_metadata(
			&mut self,
			metadata_event: crate::llm::bedrock::types::ConverseStreamMetadataEvent,
		) -> Result<Option<StreamEvent>, AIError> {
			if let Some(bedrock_usage) = metadata_event.usage {
				let usage = Usage {
					input_tokens: bedrock_usage.input_tokens as u32,
					output_tokens: bedrock_usage.output_tokens as u32,
					// Map Bedrock cache stats to Anthropic Messages format
					cache_creation_input_tokens: bedrock_usage.cache_write_input_tokens.map(|v| v as u32),
					cache_read_input_tokens: bedrock_usage.cache_read_input_tokens.map(|v| v as u32),
				};
				self.current_usage = Some(usage.clone());

				// Anthropic requires message_delta before message_stop
				let delta = MessageDelta {
					stop_reason: None,
					stop_sequence: None,
					usage: Some(usage),
				};
				return Ok(Some(StreamEvent::MessageDelta { delta }));
			}
			Ok(None)
		}

		/// Finalize the stream and clean up buffers
		/// Only emit message_stop if we haven't already processed a MessageStop event
		pub fn finalize(&mut self, already_stopped: bool) -> Result<Option<StreamEvent>, AIError> {
			// Clean up any remaining buffers
			if !self.tool_json_buffers.is_empty() {
				let total_size: usize = self.tool_json_buffers.values().map(|s| s.len()).sum();
				GLOBAL_BUFFER_USAGE.fetch_sub(total_size, Ordering::Relaxed);

				debug!(
					"clearing {} tool JSON buffers at stream end (total size: {} bytes)",
					self.tool_json_buffers.len(),
					total_size
				);
				self.tool_json_buffers.clear();
			}

			// Only emit message_stop if we haven't already processed a MessageStop event
			if already_stopped {
				debug!("Bedrock: Skipping final message_stop - already handled MessageStop event");
				Ok(None)
			} else {
				debug!("Bedrock: Emitting final message_stop - no MessageStop event was processed");
				Ok(Some(StreamEvent::MessageStop))
			}
		}
	}

	/// Serialize Anthropic StreamEvent to SSE format
	fn serialize_anthropic_event_to_sse(event: &StreamEvent) -> Result<Bytes, AIError> {
		let event_type = match event {
			StreamEvent::MessageStart { .. } => "message_start",
			StreamEvent::ContentBlockStart { .. } => "content_block_start",
			StreamEvent::Ping => "ping",
			StreamEvent::ContentBlockDelta { .. } => "content_block_delta",
			StreamEvent::ContentBlockStop { .. } => "content_block_stop",
			StreamEvent::MessageDelta { .. } => "message_delta",
			StreamEvent::MessageStop => "message_stop",
			StreamEvent::Error { .. } => "error",
		};

		let json_data = serde_json::to_string(event).map_err(AIError::ResponseMarshal)?;
		let sse_frame = format!("event: {}\ndata: {}\n\n", event_type, json_data);
		Ok(Bytes::from(sse_frame))
	}

	pin_project! {
		/// Custom Body that transforms Bedrock EventStream to Anthropic SSE inline
		pub struct AnthropicStreamBody {
			#[pin]
			upstream: Body,
			decoder: EventStreamCodec,
			decode_buffer: bytes::BytesMut,
			outbound_frames: VecDeque<Bytes>,
			processor: BedrockStreamProcessor,
			log: AsyncLog<LLMResponse>,
			rate_limit: Option<LLMResponsePolicies>,
			finished: bool,
		}
	}

	impl AnthropicStreamBody {
		pub fn new(
			upstream: Body,
			message_id: String,
			model: String,
			log: AsyncLog<LLMResponse>,
			rate_limit: Option<LLMResponsePolicies>,
		) -> Self {
			Self {
				upstream,
				decoder: EventStreamCodec,
				decode_buffer: bytes::BytesMut::new(),
				outbound_frames: VecDeque::new(),
				processor: BedrockStreamProcessor::new(message_id, model),
				log,
				rate_limit,
				finished: false,
			}
		}
	}

	impl http_body::Body for AnthropicStreamBody {
		type Data = Bytes;
		type Error = Box<dyn std::error::Error + Send + Sync>;

		fn poll_frame(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
		) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
			let mut this = self.project();

			loop {
				// 1) If we have queued frames, yield one
				if let Some(frame_data) = this.outbound_frames.pop_front() {
					return Poll::Ready(Some(Ok(http_body::Frame::data(frame_data))));
				}

				// 2) If finished and no more frames, we're done
				if *this.finished {
					return Poll::Ready(None);
				}

				// 3) Try to decode complete EventStream messages from buffer
				let mut decoded_any = false;
				loop {
					match this.decoder.decode(this.decode_buffer) {
						Ok(Some(message)) => {
							decoded_any = true;
							// Process Bedrock event → 0..N Anthropic events
							// Extract raw JSON for debug logging
							let message_body = message.body.clone();

							match ConverseStreamOutput::deserialize(message) {
								Ok(bedrock_event) => {
									debug!("Bedrock: Processing stream event: {:?}", bedrock_event);

									match this.processor.process_event(bedrock_event, this.log) {
									Ok(anthropic_events) => {
										// Convert each Anthropic event to SSE frame and queue
										for event in anthropic_events {
											let sse_bytes = serialize_anthropic_event_to_sse(&event)
												.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
											this.outbound_frames.push_back(sse_bytes);
										}
									},
									Err(_e) => {
										// Skip processing errors, continue with stream
									},
								}
								},
								Err(e) => {
									if let Ok(raw_json) = std::str::from_utf8(&message_body) {
										debug!("Bedrock: DESERIALIZATION FAILURE - JSON: {} - Error: {:?}", raw_json, e);
									} else {
										debug!("Bedrock: Failed to deserialize stream event: {:?}", e);
									}
									// Skip malformed events, continue with stream
								}
							}
						},
						Ok(None) => {
							// Need more input data
							break;
						},
						Err(_e) => {
							// Skip malformed EventStream messages
							break;
						},
					}
				}

				// If we decoded events and now have frames queued, yield one
				if decoded_any && !this.outbound_frames.is_empty() {
					continue; // Go back to step 1 to yield frame
				}

				// 4) Poll upstream for more data
				match ready!(this.upstream.as_mut().poll_frame(cx)) {
					Some(Ok(frame)) => {
						if let Some(data) = frame.data_ref() {
							this.decode_buffer.extend_from_slice(data);
							// Continue the loop to decode immediately
							continue;
						}
						// Frame with no data, poll again
						continue;
					},
					Some(Err(e)) => {
						return Poll::Ready(Some(Err(
							Box::new(e) as Box<dyn std::error::Error + Send + Sync>
						)));
					},
					None => {
						// Upstream finished - emit final message_stop and mark finished
						*this.finished = true;

						if let (Some(usage), Some(rate_limit)) =
							(&this.processor.current_usage, this.rate_limit.take())
						{
							this.log.non_atomic_mutate(|llm_resp| {
								llm_resp.input_tokens_from_response = Some(usage.input_tokens as u64);
								llm_resp.output_tokens = Some(usage.output_tokens as u64);
								llm_resp.total_tokens = Some((usage.input_tokens + usage.output_tokens) as u64);

								// Call amend_tokens with actual usage
								crate::llm::amend_tokens(rate_limit, llm_resp);
							});
						}

						match this.processor.finalize(this.processor.message_stopped) {
							Ok(Some(final_event)) => {
								let sse_bytes = serialize_anthropic_event_to_sse(&final_event)
									.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
								return Poll::Ready(Some(Ok(http_body::Frame::data(sse_bytes))));
							},
							Ok(None) => {
								// No final event needed - already handled MessageStop
								return Poll::Ready(None);
							},
							Err(_e) => {
								// No final event, just finish
								return Poll::Ready(None);
							},
						}
					},
				}
			}
		}
	}
}