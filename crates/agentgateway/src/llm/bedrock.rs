use agent_core::prelude::Strng;
use agent_core::strng;
use bytes::Bytes;
use chrono;
use itertools::Itertools;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tracing::trace;

const DEFAULT_MAX_TOKENS: usize = 4_096;

use crate::http::{Body, Response};
use crate::llm::bedrock::types::{
	ContentBlock, ConverseErrorResponse, ConverseRequest, ConverseResponse,
	StopReason,
};
use crate::llm::{AIError, LLMInfo, universal};
use crate::telemetry::log::AsyncLog;
use crate::*;
use ::http::header::CONTENT_TYPE;

#[derive(Debug, Clone)]
pub struct AwsRegion {
	pub region: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Provider {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub model: Option<Strng>, // Optional: model override for Bedrock API path
	pub region: Strng, // Required: AWS region
	#[serde(skip_serializing_if = "Option::is_none")]
	pub guardrail_identifier: Option<Strng>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub guardrail_version: Option<Strng>,
}

impl super::Provider for Provider {
	const NAME: Strng = strng::literal!("bedrock");
}

impl Provider {
	pub async fn process_request(
		&self,
		mut req: universal::Request,
	) -> Result<ConverseRequest, AIError> {
		// Use provider's model if configured, otherwise keep the request model
		if let Some(provider_model) = &self.model {
			req.model = Some(provider_model.to_string());
		} else if req.model.is_none() {
			return Err(AIError::MissingField("model not specified".into()));
		}
		let bedrock_request = translate_request(req, self);

		Ok(bedrock_request)
	}

	pub fn process_response(
		&self,
		model: &str,
		bytes: &Bytes,
		input_format: crate::llm::InputFormat,
	) -> Result<Box<dyn crate::llm::ResponseType>, AIError> {
		let model = self.model.as_deref().unwrap_or(model);
		let resp =
			serde_json::from_slice::<ConverseResponse>(bytes).map_err(AIError::ResponseParsing)?;

		match input_format {
			crate::llm::InputFormat::Completions => {
				// EXISTING PATH: Bedrock → Universal OpenAI format
				let openai_resp = translate_response(resp, model)?;
				let passthrough = crate::json::convert::<_, universal::passthrough::Response>(&openai_resp)
					.map_err(AIError::ResponseParsing)?;
				Ok(Box::new(passthrough))
			},
			crate::llm::InputFormat::Messages => {
				// NEW PATH: Bedrock → Anthropic Messages format
				let anthropic_resp = translate_response_anthropic(resp, model)?;
				Ok(Box::new(anthropic_resp))
			},
		}
	}

	pub fn process_error(
		&self,
		bytes: &Bytes,
	) -> Result<universal::ChatCompletionErrorResponse, AIError> {
		let resp =
			serde_json::from_slice::<ConverseErrorResponse>(bytes).map_err(AIError::ResponseParsing)?;
		translate_error(resp)
	}

	pub async fn process_streaming(
		&self,
		log: AsyncLog<LLMInfo>,
		resp: Response,
		model: &str,
		input_format: crate::llm::InputFormat,
	) -> Response {
		let model = self.model.as_deref().unwrap_or(model).to_string();

		let is_ok = resp.status().is_success();
		let is_eventstream = resp
			.headers()
			.get(CONTENT_TYPE)
			.and_then(|v| v.to_str().ok())
			.map(|ct| ct.starts_with("application/vnd.amazon.eventstream"))
			.unwrap_or(false);

		tracing::info!(
			"Bedrock streaming response: status={}, content_type={:?}, is_eventstream={}",
			resp.status(),
			resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
			is_eventstream
		);

		if !is_ok || !is_eventstream {
			// For error responses, try to read and log the body
			if !is_ok {
				tracing::error!(
					"Bedrock returned error status {}: Collecting error body...",
					resp.status()
				);
			}

			tracing::warn!(
				status = ?resp.status(),
				ct = ?resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
				"Upstream response is not eventstream; passing through unchanged"
			);
			return resp;
		}

		// Bedrock doesn't return an ID, so get one from the request... if we can
		let message_id = resp
			.headers()
			.get(http::x_headers::X_AMZN_REQUESTID)
			.and_then(|s| s.to_str().ok().map(|s| s.to_owned()))
			.unwrap_or_else(|| format!("{:016x}", rand::rng().random::<u64>()));

		// Add headers to disable HTTP/2 buffering and improve streaming smoothness
		let (mut parts, body) = resp.into_parts();
		parts.headers.insert(
			http::HeaderName::from_static("x-accel-buffering"),
			http::HeaderValue::from_static("no"),
		);
		parts.headers.insert(
			http::header::CACHE_CONTROL,
			http::HeaderValue::from_static("no-cache"),
		);
		let resp = Response::from_parts(parts, body);

		match input_format {
			crate::llm::InputFormat::Completions => {
				// EXISTING PATH: AWS EventStream → Universal SSE
				resp.map(|b| translate_stream(b, log.clone(), model.clone(), message_id.clone()))
			},
			crate::llm::InputFormat::Messages => {
				// NEW PATH: AWS EventStream → Anthropic SSE
				resp.map(|body| translate_stream_anthropic(body, log, model, message_id))
			},
		}
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
) -> Result<universal::Response, AIError> {
	let adapter = ConverseResponseAdapter::from_response(resp, model)?;
	Ok(adapter.to_universal())
}

fn translate_stop_reason(resp: &StopReason) -> universal::FinishReason {
	match resp {
		StopReason::EndTurn => universal::FinishReason::Stop,
		StopReason::MaxTokens => universal::FinishReason::Length,
		StopReason::StopSequence => universal::FinishReason::Stop,
		StopReason::ContentFiltered => universal::FinishReason::ContentFilter,
		StopReason::GuardrailIntervened => universal::FinishReason::ContentFilter,
		StopReason::ToolUse => universal::FinishReason::ToolCalls,
	}
}

pub(super) fn translate_request(req: universal::Request, provider: &Provider) -> ConverseRequest {
	// Bedrock has system prompts in a separate field. Join them
	let system = req
		.messages
		.iter()
		.filter_map(|msg| {
			if universal::message_role(msg) == universal::SYSTEM_ROLE {
				universal::message_text(msg).map(|s| s.to_string())
			} else {
				None
			}
		})
		.collect::<Vec<String>>()
		.join("\n");

	let messages = req
		.messages
		.iter()
		.filter(|msg| universal::message_role(msg) != universal::SYSTEM_ROLE)
		.filter_map(|msg| {
			let role = match universal::message_role(msg) {
				universal::ASSISTANT_ROLE => types::Role::Assistant,
				// Default to user for other roles
				_ => types::Role::User,
			};

			universal::message_text(msg)
				.map(|s| vec![ContentBlock::Text(s.to_string())])
				.map(|content| types::Message { role, content })
		})
		.collect();

	let inference_config = types::InferenceConfiguration {
		max_tokens: universal::max_tokens(&req),
		temperature: req.temperature,
		top_p: req.top_p,
		// Map Anthropic-style vendor extension to Bedrock topK when provided
		top_k: req.vendor_extensions.top_k.map(|v| v as usize),
		stop_sequences: universal::stop_sequence(&req),
	};

	// Build guardrail configuration if specified
	let guardrail_config = if let (Some(identifier), Some(version)) =
		(&provider.guardrail_identifier, &provider.guardrail_version)
	{
		Some(types::GuardrailConfiguration {
			guardrail_identifier: identifier.to_string(),
			guardrail_version: version.to_string(),
			trace: Some("enabled".to_string()),
		})
	} else {
		None
	};

	let metadata = req
		.user
		.map(|user| HashMap::from([("user_id".to_string(), user)]));

	let tool_choice = match req.tool_choice {
		Some(universal::ToolChoiceOption::Named(universal::NamedToolChoice {
			r#type: _,
			function,
		})) => Some(types::ToolChoice::Tool {
			name: function.name,
		}),
		Some(universal::ToolChoiceOption::Auto) => Some(types::ToolChoice::Auto),
		Some(universal::ToolChoiceOption::Required) => Some(types::ToolChoice::Any),
		Some(universal::ToolChoiceOption::None) => None,
		None => None,
	};
	let tools = req.tools.map(|tools| {
		tools
			.into_iter()
			.map(|tool| {
				let tool_spec = types::ToolSpecification {
					name: tool.function.name,
					description: tool.function.description,
					input_schema: tool.function.parameters.map(types::ToolInputSchema::Json),
				};

				types::Tool::ToolSpec(tool_spec)
			})
			.collect_vec()
	});
	let tool_config = tools.map(|tools| types::ToolConfiguration { tools, tool_choice });

	// Handle thinking configuration similar to Anthropic
	let thinking = if let Some(budget) = req.vendor_extensions.thinking_budget_tokens {
		Some(serde_json::json!({
			"thinking": {
				"type": "enabled",
				"budget_tokens": budget
			}
		}))
	} else {
		match &req.reasoning_effort {
			Some(universal::ReasoningEffort::Low) => Some(serde_json::json!({
				"thinking": {
					"type": "enabled",
					"budget_tokens": 1024
				}
			})),
			Some(universal::ReasoningEffort::Medium) => Some(serde_json::json!({
				"thinking": {
					"type": "enabled",
					"budget_tokens": 2048
				}
			})),
			Some(universal::ReasoningEffort::High) => Some(serde_json::json!({
				"thinking": {
					"type": "enabled",
					"budget_tokens": 4096
				}
			})),
			None => None,
		}
	};

	ConverseRequest {
		model_id: req.model.unwrap_or_default(),
		messages,
		system: if system.is_empty() {
			None
		} else {
			Some(vec![types::SystemContentBlock::Text { text: system }])
		},
		inference_config: Some(inference_config),
		tool_config,
		guardrail_config,
		additional_model_request_fields: thinking,
		prompt_variables: None,
		additional_model_response_field_paths: None,
		request_metadata: metadata,
		performance_config: None,
	}
}

pub(super) fn translate_stream(
	b: Body,
	log: AsyncLog<LLMInfo>,
	model: String,
	message_id: String,
) -> Body {
	let mut bridge = ConverseStreamAdapter::new(log, model, message_id);
	parse::aws_sse::transform_multi(
		b,
		move |aws_event| match types::ConverseStreamOutput::deserialize(aws_event) {
			Ok(event) => {
				let normalized_events = bridge.normalize(event);
				let mut results = Vec::new();
				for ev in normalized_events {
					for chunk in bridge.emit_universal(ev) {
						results.push(chunk);
					}
				}
				results
			},
			Err(e) => {
				tracing::error!(error = %e, "failed to deserialize bedrock stream event");
				// Emit error chunk to inform client of stream failure
				let error_chunk = universal::StreamResponse {
					id: bridge.message_id.clone(),
					model: bridge.model.clone(),
					object: "chat.completion.chunk".to_string(),
					system_fingerprint: None,
					service_tier: None,
					created: bridge.created,
					choices: vec![universal::ChatChoiceStream {
						index: 0,
						logprobs: None,
						delta: universal::StreamResponseDelta {
							content: Some("[Stream processing error]".to_string()),
							..Default::default()
						},
						finish_reason: None,
					}],
					usage: None,
				};
				vec![error_chunk]
			},
		},
	)
}

pub(super) fn translate_request_anthropic(
	req: &crate::llm::anthropic::passthrough::Request,
	provider: &Provider,
	headers: Option<&http::HeaderMap>,
) -> Result<ConverseRequest, AIError> {
	tracing::debug!(
		model = ?req.model,
		stream = ?req.stream,
		max_tokens = ?req.max_tokens,
		temperature = ?req.temperature,
		has_tools = %req.rest.get("tools").is_some(),
		has_thinking = %req.rest.get("thinking").is_some(),
		"translating anthropic request to bedrock"
	);

	let mut cache_points_used = 0;

	// Check if thinking is enabled (need this early for message filtering)
	let thinking_enabled = req.rest.get("thinking").is_some()
		|| req.rest.get("thinking_budget_tokens").is_some();

	let system_content = insert_cache_points_in_system(&req.messages, &mut cache_points_used);

	let messages: Result<Vec<types::Message>, AIError> = req
		.messages
		.iter()
		.filter(|msg| msg.role != "system") // Skip system messages
		.map(|msg| {
			let role = match msg.role.as_str() {
				"assistant" => types::Role::Assistant,
				"user" | _ => types::Role::User, // Default to user
			};

			let content_blocks: Result<Vec<ContentBlock>, AIError> = match &msg.content {
				Some(crate::llm::anthropic::passthrough::RequestContent::Text(text)) => {
					Ok(vec![ContentBlock::Text(text.clone())])
				},
				Some(crate::llm::anthropic::passthrough::RequestContent::Array(blocks)) => {
					insert_cache_points_in_content(blocks, &mut cache_points_used)
				},
				None => Ok(vec![]),
			};

			Ok(types::Message {
				role,
				content: content_blocks?,
			})
		})
		.collect();

	let messages = messages?;

	let inference_config = types::InferenceConfiguration {
		max_tokens: req.max_tokens.map(|v| v as usize).unwrap_or(DEFAULT_MAX_TOKENS),
		// When thinking is enabled, temperature/top_p/top_k must be None (Bedrock constraint)
		temperature: if thinking_enabled { None } else { req.temperature },
		top_p: if thinking_enabled { None } else { req.top_p },
		top_k: if thinking_enabled {
			None
		} else {
			req.rest.get("top_k").and_then(|v| v.as_u64()).map(|v| v as usize)
		},
		stop_sequences: req
			.rest
			.get("stop_sequences")
			.and_then(|v| v.as_array())
			.map(|arr| {
				arr
					.iter()
					.filter_map(|v| v.as_str().map(|s| s.to_string()))
					.collect()
			})
			.unwrap_or_default(),
	};

	let tool_config = if let Some(tools_value) = req.rest.get("tools") {
		let bedrock_tools = insert_cache_points_in_tools(tools_value, &mut cache_points_used);

		// Only create tool configuration if we have actual tools
		if !bedrock_tools.is_empty() {
			let tool_choice = if let Some(choice_value) = req.rest.get("tool_choice") {
				match choice_value.get("type").and_then(|t| t.as_str()) {
					Some("auto") => {
						if thinking_enabled {
							Some(types::ToolChoice::Any)
						} else {
							Some(types::ToolChoice::Auto)
						}
					},
					Some("any") => Some(types::ToolChoice::Any),
					Some("tool") => {
						if thinking_enabled {
							Some(types::ToolChoice::Any)
						} else if let Some(name) = choice_value.get("name").and_then(|n| n.as_str()) {
							Some(types::ToolChoice::Tool {
								name: name.to_string(),
							})
						} else {
							Some(types::ToolChoice::Auto)
						}
					},
					_ => {
						if thinking_enabled {
							Some(types::ToolChoice::Any)
						} else {
							Some(types::ToolChoice::Auto)
						}
					},
				}
			} else if thinking_enabled {
				Some(types::ToolChoice::Any)
			} else {
				None
			};

			Some(types::ToolConfiguration {
				tools: bedrock_tools,
				tool_choice,
			})
		} else {
			None
		}
	} else {
		None
	};

	let mut additional_fields = None;

	// 1) Pass through Anthropic's top-level `thinking` object if present
	if let Some(thinking) = req.rest.get("thinking") {
		additional_fields = Some(serde_json::json!({ "thinking": thinking }));
	}

	// 2) Back-compat: if callers send only `thinking_budget_tokens`, synthesize `thinking`
	if additional_fields.is_none() {
		if let Some(budget) = req
			.rest
			.get("thinking_budget_tokens")
			.and_then(|v| v.as_u64())
		{
			additional_fields = Some(serde_json::json!({
				"thinking": { "type": "enabled", "budget_tokens": budget }
			}));
		}
	}

	// Extract and handle beta headers
	if let Some(headers) = headers {
		if let Some(beta_array) = extract_beta_headers(headers)? {
			tracing::debug!(beta_count = %beta_array.len(), "forwarding beta headers to bedrock");

			// Add beta headers under the "anthropic_beta" key
			match additional_fields {
				Some(ref mut fields) => {
					// Add anthropic_beta array to existing fields
					if let Some(existing_obj) = fields.as_object_mut() {
						existing_obj.insert(
							"anthropic_beta".to_string(),
							serde_json::Value::Array(beta_array),
						);
					}
				},
				None => {
					// Create new additionalModelRequestFields with anthropic_beta
					let mut fields = serde_json::Map::new();
					fields.insert(
						"anthropic_beta".to_string(),
						serde_json::Value::Array(beta_array),
					);
					additional_fields = Some(serde_json::Value::Object(fields));
				},
			}
		}
	};

	// Build guardrail configuration if provider has it configured
	let guardrail_config = if let (Some(identifier), Some(version)) =
		(&provider.guardrail_identifier, &provider.guardrail_version)
	{
		Some(types::GuardrailConfiguration {
			guardrail_identifier: identifier.to_string(),
			guardrail_version: version.to_string(),
			trace: Some("enabled".to_string()),
		})
	} else {
		None
	};

	let metadata = req
		.rest
		.get("metadata")
		.and_then(|m| m.get("user_id"))
		.and_then(|user_id| user_id.as_str())
		.map(|user_id| std::collections::HashMap::from([("user_id".to_string(), user_id.to_string())]));

	let bedrock_request = ConverseRequest {
		model_id: req.model.clone().unwrap_or_default(),
		messages,
		system: if system_content.is_empty() {
			None
		} else {
			Some(system_content)
		},
		inference_config: Some(inference_config),
		tool_config,
		guardrail_config,
		additional_model_request_fields: additional_fields,
		prompt_variables: None,
		additional_model_response_field_paths: None,
		request_metadata: metadata,
		performance_config: None,
	};

	tracing::debug!(
		model_id = %bedrock_request.model_id,
		message_count = %bedrock_request.messages.len(),
		has_system = %bedrock_request.system.is_some(),
		has_tools = %bedrock_request.tool_config.is_some(),
		has_thinking = %bedrock_request.additional_model_request_fields.is_some(),
		"bedrock request prepared"
	);

	Ok(bedrock_request)
}

pub(super) fn translate_response_anthropic(
	bedrock_resp: ConverseResponse,
	model: &str,
) -> Result<crate::llm::anthropic::passthrough::Response, AIError> {
	let adapter = ConverseResponseAdapter::from_response(bedrock_resp, model)?;
	adapter.to_anthropic()
}

fn translate_stream_anthropic(
	b: Body,
	log: AsyncLog<LLMInfo>,
	model: String,
	message_id: String,
) -> Body {
	let mut bridge = ConverseStreamAdapter::new(log, model, message_id);
	parse::aws_sse::transform_multi(
		b,
		move |aws_event| {
			match types::ConverseStreamOutput::deserialize(aws_event) {
				Ok(event) => {
					let normalized_events = bridge.normalize(event);
					let mut results = Vec::new();
					for ev in normalized_events {
						for chunk in bridge.emit_anthropic(ev) {
							results.push(chunk);
						}
					}
					results
				},
				Err(e) => {
					tracing::error!(error = %e, "failed to deserialize bedrock stream event");
					// Emit error event in Anthropic Messages format
					vec![serde_json::json!({
						"type": "error",
						"error": {
							"type": "api_error",
							"message": "Stream processing error"
						}
					})]
				},
			}
		},
	)
}

fn generate_anthropic_message_id() -> String {
	let timestamp = chrono::Utc::now().timestamp_millis();
	let random: u32 = rand::random();
	format!("msg_{:x}{:08x}", timestamp, random)
}

fn translate_stop_reason_anthropic(stop_reason: StopReason) -> &'static str {
	match stop_reason {
		StopReason::EndTurn => "end_turn",
		StopReason::MaxTokens => "max_tokens",
		StopReason::StopSequence => "stop_sequence",
		StopReason::ToolUse => "tool_use",
		StopReason::ContentFiltered | StopReason::GuardrailIntervened => "refusal",
	}
}

fn to_anthropic_usage_json(usage: types::TokenUsage) -> serde_json::Value {
	serde_json::json!({
		"input_tokens": usage.input_tokens,
		"output_tokens": usage.output_tokens,
		"cache_creation_input_tokens": usage.cache_write_input_tokens,
		"cache_read_input_tokens": usage.cache_read_input_tokens,
		"cache_creation": null,
		"server_tool_use": null,
		"service_tier": null
	})
}

fn translate_content_block_to_bedrock(
	content: &serde_json::Value,
) -> Result<ContentBlock, AIError> {
	let content_type = content
		.get("type")
		.and_then(|t| t.as_str())
		.ok_or_else(|| AIError::MissingField("content block type".into()))?;

	match content_type {
		"text" => {
			let text = content
				.get("text")
				.and_then(|t| t.as_str())
				.ok_or_else(|| AIError::MissingField("text content".into()))?;
			Ok(ContentBlock::Text(text.to_string()))
		},
		"image" => {
			let source = content
				.get("source")
				.ok_or_else(|| AIError::MissingField("image source".into()))?;

			let media_type = source
				.get("media_type")
				.and_then(|t| t.as_str())
				.ok_or_else(|| AIError::MissingField("image media_type".into()))?;

			let data = source
				.get("data")
				.and_then(|d| d.as_str())
				.ok_or_else(|| AIError::MissingField("image data".into()))?;

			// Extract format from media_type (e.g., "image/png" -> "png")
			let format = media_type
				.strip_prefix("image/")
				.unwrap_or(media_type)
				.to_string();

			Ok(ContentBlock::Image(types::ImageBlock {
				format,
				source: types::ImageSource {
					bytes: data.to_string(),
				},
			}))
		},
		"tool_use" => {
			let id = content
				.get("id")
				.and_then(|i| i.as_str())
				.ok_or_else(|| AIError::MissingField("tool_use id".into()))?;

			let name = content
				.get("name")
				.and_then(|n| n.as_str())
				.ok_or_else(|| AIError::MissingField("tool_use name".into()))?;

			let input = content
				.get("input")
				.cloned()
				.unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

			Ok(ContentBlock::ToolUse(types::ToolUseBlock {
				tool_use_id: id.to_string(),
				name: name.to_string(),
				input,
			}))
		},
		"tool_result" => {
			let tool_use_id = content
				.get("tool_use_id")
				.and_then(|i| i.as_str())
				.ok_or_else(|| AIError::MissingField("tool_result tool_use_id".into()))?;

			let content_field = content
				.get("content")
				.ok_or_else(|| AIError::MissingField("tool_result content".into()))?;

			let tool_content = match content_field {
				serde_json::Value::String(s) => {
					vec![types::ToolResultContentBlock::Text(s.to_string())]
				},
				serde_json::Value::Array(parts) => {
					let mut blocks = Vec::with_capacity(parts.len());
					for part in parts {
						let content_type = part.get("type").and_then(|t| t.as_str());
						match content_type {
							Some("text") => {
								let text = part.get("text")
									.and_then(|t| t.as_str())
									.ok_or_else(|| AIError::MissingField("tool_result text content".into()))?;
								blocks.push(types::ToolResultContentBlock::Text(text.to_string()));
							},
							Some("image") => {
								// Image content block in tool result
								let source = part.get("source")
									.ok_or_else(|| AIError::MissingField("image source".into()))?;
								let media_type = source.get("media_type")
									.and_then(|t| t.as_str())
									.ok_or_else(|| AIError::MissingField("image media_type".into()))?;
								let data = source.get("data")
									.and_then(|d| d.as_str())
									.ok_or_else(|| AIError::MissingField("image data".into()))?;

								// Extract format from media_type
								let format = media_type
									.strip_prefix("image/")
									.unwrap_or(media_type)
									.to_string();

								blocks.push(types::ToolResultContentBlock::Image(types::ImageBlock {
									format,
									source: types::ImageSource {
										bytes: data.to_string(),
									},
								}));
							},
							Some("search_result") => {
								// Search result - store as JSON
								blocks.push(types::ToolResultContentBlock::Json(part.clone()));
							},
							_ => {
								// Unknown type - store as JSON to preserve data
								blocks.push(types::ToolResultContentBlock::Json(part.clone()));
							}
						}
					}

					blocks
				},
				_ => return Err(AIError::UnsupportedContent),
			};

			let status = content
				.get("is_error")
				.and_then(|e| e.as_bool())
				.map(|is_error| {
					if is_error {
						types::ToolResultStatus::Error
					} else {
						types::ToolResultStatus::Success
					}
				});

			Ok(ContentBlock::ToolResult(types::ToolResultBlock {
				tool_use_id: tool_use_id.to_string(),
				content: tool_content,
				status,
			}))
		},
		"thinking" => {
			let thinking = content
				.get("thinking")
				.and_then(|t| t.as_str())
				.ok_or_else(|| AIError::MissingField("thinking content".into()))?;

			// Check if signature is present (required for multi-turn conversations)
			let signature = content
				.get("signature")
				.and_then(|s| s.as_str())
				.map(|s| s.to_string());

			Ok(ContentBlock::ReasoningContent(
				if let Some(sig) = signature {
					// Use Structured format when signature is present
					types::ReasoningContentBlock::Structured {
						reasoning_text: types::ReasoningText {
							text: thinking.to_string(),
							signature: Some(sig),
						},
					}
				} else {
					// Use Simple format when no signature
					types::ReasoningContentBlock::Simple {
						text: thinking.to_string(),
					}
				},
			))
		},
		"reasoningContent" => {
			// Handle reasoningContent format (used when Claude returns thinking blocks)
			let text = content
				.get("text")
				.and_then(|t| t.as_str())
				.ok_or_else(|| AIError::MissingField("reasoningContent text".into()))?;

			Ok(ContentBlock::ReasoningContent(
				types::ReasoningContentBlock::Simple {
					text: text.to_string(),
				},
			))
		},
		"document" => Err(AIError::UnsupportedContent),
		"search_result" => Err(AIError::UnsupportedContent),
		_ => Err(AIError::UnsupportedContent),
	}
}

fn translate_content_block_to_anthropic(block: &ContentBlock) -> Option<serde_json::Value> {
	match block {
		ContentBlock::Text(text) => Some(serde_json::json!({
			"type": "text",
			"text": text
		})),
		ContentBlock::ReasoningContent(reasoning) => {
			// Extract text and signature from either format
			match reasoning {
				types::ReasoningContentBlock::Structured { reasoning_text } => {
					let mut json = serde_json::json!({
						"type": "thinking",
						"thinking": &reasoning_text.text
					});
					// Include signature if present (required for multi-turn conversations)
					if let Some(sig) = &reasoning_text.signature {
						json["signature"] = serde_json::Value::String(sig.clone());
					}
					Some(json)
				},
				types::ReasoningContentBlock::Simple { text } => {
					// Simple format doesn't have signature
					Some(serde_json::json!({
						"type": "thinking",
						"thinking": text
					}))
				}
			}
		},
		ContentBlock::ToolUse(tool_use) => Some(serde_json::json!({
			"type": "tool_use",
			"id": tool_use.tool_use_id,
			"name": tool_use.name,
			"input": tool_use.input
		})),
		ContentBlock::Image(img) => Some(serde_json::json!({
			"type": "image",
			"source": {
				"type": "base64",
				"media_type": format!("image/{}", img.format),
				"data": img.source.bytes
			}
		})),
		ContentBlock::ToolResult(_) => None, // Skip tool results in responses
		ContentBlock::CachePoint(_) => None, // Skip cache points - they're metadata only
	}
}

fn create_cache_point() -> types::CachePointBlock {
	types::CachePointBlock {
		r#type: types::CachePointType::Default,
	}
}

fn insert_cache_points_in_content(
	content_blocks: &[crate::llm::anthropic::passthrough::ContentPart],
	cache_points_used: &mut usize,
) -> Result<Vec<types::ContentBlock>, AIError> {
	let mut result = Vec::with_capacity(content_blocks.len() * 2);

	for block in content_blocks {
		let json_block = serde_json::to_value(block).map_err(|e| AIError::RequestParsing(e))?;
		let bedrock_block = translate_content_block_to_bedrock(&json_block)?;
		result.push(bedrock_block);

		if let Some(cache_control) = block.rest.get("cache_control")
			&& let Some(cache_type) = cache_control.get("type")
			&& cache_type.as_str() == Some("ephemeral")
			&& *cache_points_used < 4
		{
			result.push(types::ContentBlock::CachePoint(create_cache_point()));
			*cache_points_used += 1;
		}
	}

	Ok(result)
}

fn insert_cache_points_in_system(
	messages: &[crate::llm::anthropic::passthrough::RequestMessage],
	cache_points_used: &mut usize,
) -> Vec<types::SystemContentBlock> {
	let mut result = Vec::new();

	for msg in messages {
		if msg.role == "system" {
			match &msg.content {
				Some(crate::llm::anthropic::passthrough::RequestContent::Text(text)) => {
					result.push(types::SystemContentBlock::Text { text: text.clone() });

					if let Some(cache_control) = msg.rest.get("cache_control")
						&& let Some(cache_type) = cache_control.get("type")
						&& cache_type.as_str() == Some("ephemeral")
						&& *cache_points_used < 4
					{
						result.push(types::SystemContentBlock::CachePoint(create_cache_point()));
						*cache_points_used += 1;
					}
				},
				Some(crate::llm::anthropic::passthrough::RequestContent::Array(blocks)) => {
					for block in blocks {
						if block.r#type == "text" {
							if let Some(text) = &block.text {
								result.push(types::SystemContentBlock::Text { text: text.clone() });

								if let Some(cache_control) = block.rest.get("cache_control")
									&& let Some(cache_type) = cache_control.get("type")
									&& cache_type.as_str() == Some("ephemeral")
									&& *cache_points_used < 4
								{
									result.push(types::SystemContentBlock::CachePoint(create_cache_point()));
									*cache_points_used += 1;
								}
							}
						}
					}
				},
				None => {},
			}
		}
	}

	result
}

fn insert_cache_points_in_tools(
	tools_array: &serde_json::Value,
	cache_points_used: &mut usize,
) -> Vec<types::Tool> {
	let mut result = Vec::new();

	if let Some(tools) = tools_array.as_array() {
		for tool in tools {
			if let (Some(name), input_schema) = (
				tool.get("name").and_then(|n| n.as_str()),
				tool.get("input_schema"),
			) {
				let description = tool
					.get("description")
					.and_then(|d| d.as_str())
					.map(|s| s.to_string());

				result.push(types::Tool::ToolSpec(types::ToolSpecification {
					name: name.to_string(),
					description,
					input_schema: input_schema.cloned().map(types::ToolInputSchema::Json),
				}));

				if let Some(cache_control) = tool.get("cache_control")
					&& let Some(cache_type) = cache_control.get("type")
					&& cache_type.as_str() == Some("ephemeral")
					&& *cache_points_used < 4
				{
					result.push(types::Tool::CachePoint(create_cache_point()));
					*cache_points_used += 1;
				}
			}
		}
	}

	result
}

fn extract_beta_headers(
	headers: &http::HeaderMap,
) -> Result<Option<Vec<serde_json::Value>>, AIError> {
	let mut beta_features = Vec::new();

	// Collect all anthropic-beta header values
	for value in headers.get_all("anthropic-beta") {
		let header_str = value
			.to_str()
			.map_err(|_| AIError::MissingField("Invalid anthropic-beta header value".into()))?;

		// Handle comma-separated values within a single header
		for feature in header_str.split(',') {
			let trimmed = feature.trim();
			if !trimmed.is_empty() {
				// Add each beta feature as a string value in the array
				beta_features.push(serde_json::Value::String(trimmed.to_string()));
			}
		}
	}

	if beta_features.is_empty() {
		Ok(None)
	} else {
		Ok(Some(beta_features))
	}
}

struct ConverseResponseAdapter {
	model: String,
	stop_reason: StopReason,
	usage: Option<types::TokenUsage>,
	message: types::Message,
}

impl ConverseResponseAdapter {
	fn from_response(resp: ConverseResponse, model: &str) -> Result<Self, AIError> {
		let ConverseResponse {
			output,
			stop_reason,
			usage,
			metrics: _,
			trace,
			additional_model_response_fields: _,
			performance_config: _,
		} = resp;

		if let Some(trace) = trace.as_ref()
			&& let Some(guardrail_trace) = &trace.guardrail
		{
			trace!("Bedrock guardrail trace: {:?}", guardrail_trace);
		}

		let message = match output {
			Some(types::ConverseOutput::Message(msg)) => msg,
			_ => return Err(AIError::IncompleteResponse),
		};

		Ok(Self {
			model: model.to_string(),
			stop_reason,
			usage,
			message,
		})
	}

	fn to_universal(&self) -> universal::Response {
		let mut tool_calls: Vec<universal::MessageToolCall> = Vec::new();
		let mut content = None;
		let mut reasoning_content = None;
		for block in &self.message.content {
			match block {
				ContentBlock::Text(text) => {
					content = Some(text.clone());
				},
				ContentBlock::ReasoningContent(reasoning) => {
					// Extract text from either format
					let text = match reasoning {
						types::ReasoningContentBlock::Structured { reasoning_text } => {
							reasoning_text.text.clone()
						},
						types::ReasoningContentBlock::Simple { text } => text.clone(),
					};
					reasoning_content = Some(text);
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
				ContentBlock::Image(_) | ContentBlock::ToolResult(_) | ContentBlock::CachePoint(_) => {
					continue;
				},
			}
		}

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
			extra: None,
			reasoning_content,
		};

		let choice = universal::ChatChoice {
			index: 0,
			message,
			finish_reason: Some(translate_stop_reason(&self.stop_reason)),
			logprobs: None,
		};

		let usage = self
			.usage
			.map(|token_usage| universal::Usage {
				prompt_tokens: token_usage.input_tokens as u32,
				completion_tokens: token_usage.output_tokens as u32,
				total_tokens: token_usage.total_tokens as u32,
				prompt_tokens_details: None,
				completion_tokens_details: None,
			})
			.unwrap_or_default();

		universal::Response {
			id: format!("bedrock-{}", chrono::Utc::now().timestamp_millis()),
			object: "chat.completion".to_string(),
			created: chrono::Utc::now().timestamp() as u32,
			model: self.model.clone(),
			choices: vec![choice],
			usage: Some(usage),
			service_tier: None,
			system_fingerprint: None,
		}
	}

	fn to_anthropic(&self) -> Result<crate::llm::anthropic::passthrough::Response, AIError> {
		let content_blocks: Vec<serde_json::Value> = self
			.message
			.content
			.iter()
			.filter_map(translate_content_block_to_anthropic)
			.collect();

		let usage = self
			.usage
			.map(|usage| {
				serde_json::json!({
					"input_tokens": usage.input_tokens,
					"output_tokens": usage.output_tokens,
					"cache_creation_input_tokens": usage.cache_write_input_tokens,
					"cache_read_input_tokens": usage.cache_read_input_tokens,
					"cache_creation": null,
					"server_tool_use": null,
					"service_tier": null
				})
			})
			.unwrap_or_else(|| {
				serde_json::json!({
					"input_tokens": 0,
					"output_tokens": 0,
					"cache_creation_input_tokens": null,
					"cache_read_input_tokens": null,
					"cache_creation": null,
					"server_tool_use": null,
					"service_tier": null
				})
			});

		let anthropic_response = serde_json::json!({
			"id": generate_anthropic_message_id(),
			"type": "message",
			"role": "assistant",
			"content": content_blocks,
			"model": self.model.clone(),
			"stop_reason": translate_stop_reason_anthropic(self.stop_reason),
			"stop_sequence": null,
			"usage": usage,
			"container": null
		});

		serde_json::from_value::<crate::llm::anthropic::passthrough::Response>(anthropic_response)
			.map_err(AIError::ResponseParsing)
	}
}

struct ConverseStreamAdapter {
	log: AsyncLog<LLMInfo>,
	model: String,
	message_id: String,
	created: u32,
	saw_token: bool,
	anthropic: AnthropicStreamState,
}

impl ConverseStreamAdapter {
	fn new(log: AsyncLog<LLMInfo>, model: String, message_id: String) -> Self {
		Self {
			created: chrono::Utc::now().timestamp() as u32,
			log,
			model,
			message_id,
			saw_token: false,
			anthropic: AnthropicStreamState::default(),
		}
	}

	fn normalize(&mut self, event: types::ConverseStreamOutput) -> Vec<types::BedrockStreamEvent> {
		match event {
			types::ConverseStreamOutput::MessageStart(start) => {
				vec![types::BedrockStreamEvent::MessageStart { role: start.role }]
			}
			types::ConverseStreamOutput::ContentBlockStart(start) => {
				// Bedrock only sends start for tool blocks; mark as seen and pass through
				self.anthropic.seen_blocks.insert(start.content_block_index);
				vec![types::BedrockStreamEvent::ContentStart {
					index: start.content_block_index,
					start: match start.start {
						Some(s) => s,
						None => types::ContentBlockStart::Text, // defensive fallback
					},
				}]
			}
			types::ConverseStreamOutput::ContentBlockDelta(delta) => {
				let mut out = Vec::new();

				// synthesize ContentStart for first text/thinking delta on this index
				let first_for_index = !self.anthropic.seen_blocks.contains(&delta.content_block_index);
				if first_for_index {
					self.anthropic.seen_blocks.insert(delta.content_block_index);

					if let Some(ref d) = delta.delta {
						match d {
							types::ContentBlockDelta::Text(_) => out.push(
								types::BedrockStreamEvent::ContentStart {
									index: delta.content_block_index,
									start: types::ContentBlockStart::Text,
								},
							),
							types::ContentBlockDelta::ReasoningContent(_) => out.push(
								types::BedrockStreamEvent::ContentStart {
									index: delta.content_block_index,
									start: types::ContentBlockStart::ReasoningContent,
								},
							),
							types::ContentBlockDelta::ToolUse(_) => {
								// Tool deltas should have a real start already; don't synthesize
							}
						}
					}
				}

				if let Some(d) = delta.delta {
					// first token timing for either stream
					self.record_first_token();
					out.push(types::BedrockStreamEvent::ContentDelta {
						index: delta.content_block_index,
						delta: d,
					});
				}
				out
			}
			types::ConverseStreamOutput::ContentBlockStop(stop) => {
				self.anthropic.seen_blocks.remove(&stop.content_block_index);
				vec![types::BedrockStreamEvent::ContentStop {
					index: stop.content_block_index,
				}]
			}
			types::ConverseStreamOutput::MessageStop(stop) => {
				// buffer stop reason; don't emit yet
				self.anthropic.pending_stop_reason = Some(stop.stop_reason);
				vec![]
			}
			types::ConverseStreamOutput::Metadata(meta) => {
				// capture usage; update log
				if let Some(usage) = meta.usage {
					self.anthropic.pending_usage = Some(usage);
					self.update_usage(usage);
				}

				// now coalesce stop+usage into a single MessageDelta, then MessageStop
				let mut out = Vec::new();
				if let Some(stop) = self.anthropic.pending_stop_reason.take() {
					out.push(types::BedrockStreamEvent::MessageDelta {
						stop,
						usage: self.anthropic.pending_usage.take(),
					});
				}
				out.push(types::BedrockStreamEvent::MessageStop);
				out
			}
		}
	}

	fn emit_anthropic(&mut self, ev: types::BedrockStreamEvent) -> Vec<serde_json::Value> {
		match ev {
			types::BedrockStreamEvent::MessageStart { role: _ } => vec![serde_json::json!({
				"type": "message_start",
				"message": {
					"id": generate_anthropic_message_id(),
					"type": "message",
					"role": "assistant",
					"content": [],
					"model": self.model.as_str(),
					"stop_reason": null,
					"stop_sequence": null,
					"usage": {
						"input_tokens": 0,
						"output_tokens": 0,
						"cache_creation_input_tokens": null,
						"cache_read_input_tokens": null
					}
				}
			})],

			types::BedrockStreamEvent::ContentStart { index, start } => {
				let content_block = match start {
					types::ContentBlockStart::ToolUse(s) => serde_json::json!({
						"type": "tool_use",
						"id": s.tool_use_id,
						"name": s.name,
						"input": {}
					}),
					types::ContentBlockStart::ReasoningContent => serde_json::json!({
						"type": "thinking",
						"thinking": ""
					}),
					types::ContentBlockStart::Text => serde_json::json!({
						"type": "text",
						"text": ""
					}),
				};
				vec![serde_json::json!({
					"type": "content_block_start",
					"index": index,
					"content_block": content_block
				})]
			}

			types::BedrockStreamEvent::ContentDelta { index, delta } => {
				let v = match delta {
					types::ContentBlockDelta::Text(text) => serde_json::json!({
						"type": "content_block_delta",
						"index": index,
						"delta": { "type": "text_delta", "text": text }
					}),
					types::ContentBlockDelta::ReasoningContent(rc) => match rc {
						types::ReasoningContentBlockDelta::Text(t) => serde_json::json!({
							"type": "content_block_delta",
							"index": index,
							"delta": { "type": "thinking_delta", "thinking": t }
						}),
						types::ReasoningContentBlockDelta::RedactedContent(_) => serde_json::json!({
							"type": "content_block_delta",
							"index": index,
							"delta": { "type": "thinking_delta", "thinking": "[REDACTED]" }
						}),
						types::ReasoningContentBlockDelta::Signature(sig) => serde_json::json!({
							"type": "content_block_delta",
							"index": index,
							"delta": { "type": "signature_delta", "signature": sig }
						}),
						types::ReasoningContentBlockDelta::Unknown => {
							tracing::warn!("Encountered unknown reasoning content type, skipping");
							// Return empty result for this specific event, but don't exit the entire function
							serde_json::json!({
								"type": "content_block_delta",
								"index": index,
								"delta": { "type": "thinking_delta", "thinking": "" }
							})
						}
					},
					types::ContentBlockDelta::ToolUse(tu) => serde_json::json!({
						"type": "content_block_delta",
						"index": index,
						"delta": { "type": "input_json_delta", "partial_json": tu.input }
					}),
				};
				vec![v]
			}

			types::BedrockStreamEvent::ContentStop { index } => vec![serde_json::json!({
				"type": "content_block_stop",
				"index": index
			})],

			types::BedrockStreamEvent::MessageDelta { stop, usage } => {
				let mut delta = serde_json::json!({
					"type": "message_delta",
					"delta": {
						"stop_reason": translate_stop_reason_anthropic(stop),
						"stop_sequence": null
					}
				});
				if let Some(u) = usage {
					if let Some(obj) = delta.as_object_mut() {
						obj.insert("usage".into(), to_anthropic_usage_json(u));
					}
				}
				vec![delta]
			}

			types::BedrockStreamEvent::MessageStop => vec![serde_json::json!({
				"type": "message_stop"
			})],
		}
	}

	fn emit_universal(&mut self, ev: types::BedrockStreamEvent) -> Vec<universal::StreamResponse> {
		match ev {
			types::BedrockStreamEvent::MessageStart { role } => {
				let universal_role = match role {
					types::Role::Assistant => universal::Role::Assistant,
					types::Role::User => universal::Role::User,
				};
				let choice = universal::ChatChoiceStream {
					index: 0,
					logprobs: None,
					delta: universal::StreamResponseDelta {
						role: Some(universal_role),
						..Default::default()
					},
					finish_reason: None,
				};
				vec![universal::StreamResponse {
					id: self.message_id.clone(),
					model: self.model.clone(),
					object: "chat.completion.chunk".to_string(),
					system_fingerprint: None,
					service_tier: None,
					created: self.created,
					choices: vec![choice],
					usage: None,
				}]
			}

			types::BedrockStreamEvent::ContentStart { .. } => {
				// Universal doesn't need a start event (no tool-call streaming yet).
				vec![]
			}

			types::BedrockStreamEvent::ContentDelta { delta, .. } => {
				let mut d = universal::StreamResponseDelta::default();
				match delta {
					types::ContentBlockDelta::Text(t) => {
						d.content = Some(t);
					}
					types::ContentBlockDelta::ReasoningContent(rc) => {
						match rc {
							types::ReasoningContentBlockDelta::Text(t) => d.reasoning_content = Some(t),
							types::ReasoningContentBlockDelta::RedactedContent(_) => d.reasoning_content = Some("[REDACTED]".to_string()),
							types::ReasoningContentBlockDelta::Signature(_) | types::ReasoningContentBlockDelta::Unknown => { /* skip */ }
						}
					}
					types::ContentBlockDelta::ToolUse(_) => {
						// If/when you support tool-call streaming in universal, encode it here.
					}
				}
				let choice = universal::ChatChoiceStream {
					index: 0,
					logprobs: None,
					delta: d,
					finish_reason: None,
				};
				vec![universal::StreamResponse {
					id: self.message_id.clone(),
					model: self.model.clone(),
					object: "chat.completion.chunk".to_string(),
					system_fingerprint: None,
					service_tier: None,
					created: self.created,
					choices: vec![choice],
					usage: None,
				}]
			}

			types::BedrockStreamEvent::ContentStop { .. } => vec![],

			types::BedrockStreamEvent::MessageDelta { stop, usage } => {
				// 1) Finish chunk
				let finish = universal::StreamResponse {
					id: self.message_id.clone(),
					model: self.model.clone(),
					object: "chat.completion.chunk".to_string(),
					system_fingerprint: None,
					service_tier: None,
					created: self.created,
					choices: vec![universal::ChatChoiceStream {
						index: 0,
						logprobs: None,
						delta: Default::default(),
						finish_reason: Some(translate_stop_reason(&stop)),
					}],
					usage: None,
				};

				// 2) Usage-only chunk (if any) — match previous behavior
				let usage_frame = usage.map(|u| universal::StreamResponse {
					id: self.message_id.clone(),
					model: self.model.clone(),
					object: "chat.completion.chunk".to_string(),
					system_fingerprint: None,
					service_tier: None,
					created: self.created,
					choices: vec![],
					// Build the struct directly; don't call update_usage() again (we already did in normalize)
					usage: Some(universal::Usage {
						prompt_tokens: u.input_tokens as u32,
						completion_tokens: u.output_tokens as u32,
						total_tokens: u.total_tokens as u32,
						prompt_tokens_details: None,
						completion_tokens_details: None,
					}),
				});

				let mut out = vec![finish];
				if let Some(u) = usage_frame { out.push(u); }
				out
			}

			types::BedrockStreamEvent::MessageStop => vec![],
		}
	}

	fn record_first_token(&mut self) {
		if self.saw_token {
			return;
		}
		self.saw_token = true;
		self.log.non_atomic_mutate(|r| {
			r.response.first_token = Some(Instant::now());
		});
	}

	fn update_usage(&mut self, usage: types::TokenUsage) -> universal::Usage {
		self.log.non_atomic_mutate(|r| {
			r.response.output_tokens = Some(usage.output_tokens as u64);
			r.response.input_tokens = Some(usage.input_tokens as u64);
			r.response.total_tokens = Some(usage.total_tokens as u64);
			r.response.cache_read_input_tokens = usage.cache_read_input_tokens.map(|v| v as u64);
			r.response.cache_write_input_tokens = usage.cache_write_input_tokens.map(|v| v as u64);
		});

		universal::Usage {
			prompt_tokens: usage.input_tokens as u32,
			completion_tokens: usage.output_tokens as u32,
			total_tokens: usage.total_tokens as u32,
			prompt_tokens_details: None,
			completion_tokens_details: None,
		}
	}
}

#[cfg(test)]
impl ConverseStreamAdapter {
	fn anthropic_event(&mut self, event: types::ConverseStreamOutput) -> Vec<serde_json::Value> {
		self.normalize(event)
			.into_iter()
			.flat_map(|ev| self.emit_anthropic(ev))
			.collect()
	}
}

#[derive(Default)]
struct AnthropicStreamState {
	seen_blocks: HashSet<i32>,
	pending_stop_reason: Option<types::StopReason>,
	pending_usage: Option<types::TokenUsage>,
}

#[cfg(test)]
mod tests {
	use super::*;
	use ::http::HeaderMap;
	use serde_json::json;

	#[test]
	fn test_translate_request_anthropic_maps_top_k_from_passthrough() {
		let provider = Provider {
			model: Some(strng::new("anthropic.claude-3")),
			region: strng::new("us-east-1"),
			guardrail_identifier: None,
			guardrail_version: None,
		};

		let req = crate::llm::anthropic::passthrough::Request {
			model: Some("anthropic.claude-3".to_string()),
			messages: vec![crate::llm::anthropic::passthrough::RequestMessage {
				role: "user".to_string(),
				content: Some(crate::llm::anthropic::passthrough::RequestContent::Text(
					"hello".to_string(),
				)),
				rest: serde_json::Value::Null,
			}],
			top_p: Some(0.9),
			temperature: Some(0.7),
			stream: Some(false),
			max_tokens: Some(256),
			rest: serde_json::json!({
				"top_k": 7
			}),
		};

		let out = translate_request_anthropic(&req, &provider, None).unwrap();
		let inf = out.inference_config.unwrap();
		assert_eq!(inf.top_k, Some(7));
	}

	#[test]
	fn test_extract_beta_headers_variants() {
		let headers = HeaderMap::new();
		assert!(extract_beta_headers(&headers).unwrap().is_none());

		let mut headers = HeaderMap::new();
		headers.insert(
			"anthropic-beta",
			"prompt-caching-2024-07-31".parse().unwrap(),
		);
		assert_eq!(
			extract_beta_headers(&headers).unwrap().unwrap(),
			vec![json!("prompt-caching-2024-07-31")]
		);

		let mut headers = HeaderMap::new();
		headers.insert(
			"anthropic-beta",
			"cache-control-2024-08-15,computer-use-2024-10-22"
				.parse()
				.unwrap(),
		);
		assert_eq!(
			extract_beta_headers(&headers).unwrap().unwrap(),
			vec![
				json!("cache-control-2024-08-15"),
				json!("computer-use-2024-10-22"),
			]
		);

		let mut headers = HeaderMap::new();
		headers.insert(
			"anthropic-beta",
			" cache-control-2024-08-15 , computer-use-2024-10-22 "
				.parse()
				.unwrap(),
		);
		assert_eq!(
			extract_beta_headers(&headers).unwrap().unwrap(),
			vec![
				json!("cache-control-2024-08-15"),
				json!("computer-use-2024-10-22"),
			]
		);

		let mut headers = HeaderMap::new();
		headers.append(
			"anthropic-beta",
			"cache-control-2024-08-15".parse().unwrap(),
		);
		headers.append("anthropic-beta", "computer-use-2024-10-22".parse().unwrap());
		let mut beta_features = extract_beta_headers(&headers)
			.unwrap()
			.unwrap()
			.into_iter()
			.map(|v| v.as_str().unwrap().to_string())
			.collect::<Vec<_>>();
		beta_features.sort();
		assert_eq!(
			beta_features,
			vec![
				"cache-control-2024-08-15".to_string(),
				"computer-use-2024-10-22".to_string(),
			]
		);
	}

	#[test]
	fn test_text_delta_synthesizes_start() {
		let log = AsyncLog::default();
		let mut bridge =
			ConverseStreamAdapter::new(log, "bedrock-model".to_string(), "message-id".to_string());

			let delta_event =
			types::ConverseStreamOutput::ContentBlockDelta(types::ContentBlockDeltaEvent {
				delta: Some(types::ContentBlockDelta::Text("partial".to_string())),
				content_block_index: 0,
			});
		let events = bridge.anthropic_event(delta_event);
		assert_eq!(events.len(), 2);
		// First event should be the synthesized start
		assert_eq!(events[0]["type"], "content_block_start");
		assert_eq!(events[0]["content_block"]["type"], "text");
		// Second event should be the delta
		assert_eq!(events[1]["type"], "content_block_delta");
		assert_eq!(events[1]["delta"]["text"], "partial");

		// Second delta for same block should not synthesize another start
		let second_delta =
			types::ConverseStreamOutput::ContentBlockDelta(types::ContentBlockDeltaEvent {
				delta: Some(types::ContentBlockDelta::Text(" more text".to_string())),
				content_block_index: 0,
			});
		let events = bridge.anthropic_event(second_delta);
		assert_eq!(events.len(), 1);
		assert_eq!(events[0]["type"], "content_block_delta");
		assert_eq!(events[0]["delta"]["text"], " more text");
	}

	#[test]
	fn test_tool_block_uses_real_start() {
		let log = AsyncLog::default();
		let mut bridge =
			ConverseStreamAdapter::new(log, "bedrock-model".to_string(), "message-id".to_string());

		// Tool blocks should get real ContentBlockStart from Bedrock
		let start_event =
			types::ConverseStreamOutput::ContentBlockStart(types::ContentBlockStartEvent {
				start: Some(types::ContentBlockStart::ToolUse(
					types::ToolUseBlockStart {
						tool_use_id: "tool_123".to_string(),
						name: "search".to_string(),
					},
				)),
				content_block_index: 0,
			});
		let events = bridge.anthropic_event(start_event);
		assert_eq!(events.len(), 1);
		assert_eq!(events[0]["type"], "content_block_start");
		assert_eq!(events[0]["content_block"]["type"], "tool_use");
		assert_eq!(events[0]["content_block"]["id"], "tool_123");
		assert_eq!(events[0]["content_block"]["name"], "search");

		// Tool delta should not synthesize a start
		let delta_event =
			types::ConverseStreamOutput::ContentBlockDelta(types::ContentBlockDeltaEvent {
				delta: Some(types::ContentBlockDelta::ToolUse(
					types::ToolUseBlockDelta {
						input: r#"{"query": "weather"}"#.to_string(),
					},
				)),
				content_block_index: 0,
			});
		let events = bridge.anthropic_event(delta_event);
		assert_eq!(events.len(), 1);
		assert_eq!(events[0]["type"], "content_block_delta");
		assert_eq!(
			events[0]["delta"]["partial_json"],
			r#"{"query": "weather"}"#
		);
	}

	#[test]
	fn test_metadata_emits_message_delta_with_usage() {
		let log = AsyncLog::default();
		let mut bridge =
			ConverseStreamAdapter::new(log, "bedrock-model".to_string(), "message-id".to_string());

		// MessageStop should not emit events immediately but store the stop reason.
		let stop_events = bridge.anthropic_event(types::ConverseStreamOutput::MessageStop(
			types::MessageStopEvent {
				stop_reason: StopReason::EndTurn,
				additional_model_response_fields: None,
			},
		));
		assert!(stop_events.is_empty());

		let usage = types::TokenUsage {
			input_tokens: 10,
			output_tokens: 5,
			total_tokens: 15,
			cache_read_input_tokens: Some(2),
			cache_write_input_tokens: Some(3),
		};

		let events = bridge.anthropic_event(types::ConverseStreamOutput::Metadata(
			types::ConverseStreamMetadataEvent {
				usage: Some(usage),
				metrics: None,
				performance_config: None,
			},
		));

		assert_eq!(events.len(), 2);
		assert_eq!(events[0]["type"], "message_delta");
		assert_eq!(events[0]["delta"]["stop_reason"], "end_turn");
		assert_eq!(events[0]["usage"]["input_tokens"], json!(10));
		assert_eq!(events[0]["usage"]["output_tokens"], json!(5));
		assert_eq!(events[0]["usage"]["cache_read_input_tokens"], json!(2));
		assert_eq!(events[0]["usage"]["cache_creation"], json!(null));
		assert_eq!(events[1]["type"], "message_stop");
	}
}

pub(super) mod types {
	use bytes::Bytes;
	use serde::{Deserialize, Serialize};
	use std::collections::HashMap;

	#[derive(Clone, Debug)]
	pub enum BedrockStreamEvent {
		MessageStart { role: Role },
		ContentStart { index: i32, start: ContentBlockStart },
		ContentDelta { index: i32, delta: ContentBlockDelta },
		ContentStop { index: i32 },
		MessageDelta { stop: StopReason, usage: Option<TokenUsage> },
		MessageStop,
	}

	#[derive(Copy, Clone, Deserialize, Serialize, Debug, Default)]
	#[serde(rename_all = "camelCase")]
	pub enum Role {
		#[default]
		User,
		Assistant,
	}

	#[derive(Clone, Deserialize, Serialize, Debug)]
	#[serde(rename_all = "camelCase")]
	pub enum ContentBlock {
		Text(String),
		Image(ImageBlock),
			ToolResult(ToolResultBlock),
		ToolUse(ToolUseBlock),
		ReasoningContent(ReasoningContentBlock),
		CachePoint(CachePointBlock),
	}

	#[derive(Clone, Deserialize, Serialize, Debug)]
	#[serde(rename_all = "camelCase")]
	pub struct ImageBlock {
		pub format: String,
		pub source: ImageSource,
	}

	#[derive(Clone, Deserialize, Serialize, Debug)]
	#[serde(rename_all = "camelCase")]
	pub struct ImageSource {
		pub bytes: String,
	}


	#[derive(Clone, Deserialize, Serialize, Debug)]
	#[serde(untagged)]
	pub enum ReasoningContentBlock {
		// New format from Bedrock: { "reasoningText": { "text": "...", "signature": "..." } }
		Structured {
			#[serde(rename = "reasoningText")]
			reasoning_text: ReasoningText,
		},
		// Legacy/simple format: { "text": "..." }
		Simple {
			text: String,
		},
	}

	#[derive(Clone, Deserialize, Serialize, Debug)]
	#[serde(rename_all = "camelCase")]
	pub struct ReasoningText {
		pub text: String,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pub signature: Option<String>,
	}
	#[derive(Clone, Deserialize, Serialize, Debug)]
	#[serde(rename_all = "camelCase")]
	pub struct ToolResultBlock {
		/// The ID of the tool request that this is the result for.
		pub tool_use_id: String,
		/// The content for tool result content block.
		pub content: Vec<ToolResultContentBlock>,
		/// The status for the tool result content block.
		/// This field is only supported Anthropic Claude 3 models.
		pub status: Option<ToolResultStatus>,
	}

	#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
	#[serde(rename_all = "camelCase")]
	pub enum ToolResultStatus {
		Error,
		Success,
	}

	#[derive(Clone, Deserialize, Serialize, Debug)]
	#[serde(rename_all = "camelCase")]
	pub struct ToolUseBlock {
		/// The ID for the tool request.
		pub tool_use_id: String,
		/// The name of the tool that the model wants to use.
		pub name: String,
		/// The input to pass to the tool.
		pub input: serde_json::Value,
	}

	#[derive(Clone, Deserialize, Serialize, Debug)]
	#[serde(rename_all = "camelCase")]
	pub enum ToolResultContentBlock {
		/// A tool result that is text.
		Text(String),
		/// A tool result that is an image.
		Image(ImageBlock),
		/// A tool result that is JSON format data.
		Json(serde_json::Value),
		/// A tool result that is video.
		Video(serde_json::Value),
	}
	#[derive(Clone, Deserialize, Serialize, Debug)]
	#[serde(rename_all = "camelCase")]
	#[serde(untagged)]
	pub enum SystemContentBlock {
		Text { text: String },
		CachePoint(CachePointBlock),
	}

	#[derive(Clone, Deserialize, Serialize, Debug)]
	#[serde(rename_all = "camelCase")]
	pub struct Message {
		pub role: Role,
		pub content: Vec<ContentBlock>,
	}

	#[derive(Clone, Serialize, Debug, PartialEq)]
	pub struct InferenceConfiguration {
		/// The maximum number of tokens to generate before stopping.
		#[serde(rename = "maxTokens")]
		pub max_tokens: usize,
		/// Amount of randomness injected into the response.
		#[serde(skip_serializing_if = "Option::is_none")]
		pub temperature: Option<f32>,
		/// Use nucleus sampling.
		#[serde(skip_serializing_if = "Option::is_none")]
		pub top_p: Option<f32>,
		/// Only sample from the top K options for each subsequent token (if supported by model).
		#[serde(rename = "topK", skip_serializing_if = "Option::is_none")]
		pub top_k: Option<usize>,
		/// The stop sequences to use.
		#[serde(rename = "stopSequences", skip_serializing_if = "Vec::is_empty")]
		pub stop_sequences: Vec<String>,
	}

	#[derive(Clone, Serialize, Debug)]
	pub struct ConverseRequest {
		/// Specifies the model or throughput with which to run inference.
		#[serde(rename = "modelId")]
		pub model_id: String,
		/// The messages that you want to send to the model.
		pub messages: Vec<Message>,
		/// A prompt that provides instructions or context to the model.
		#[serde(skip_serializing_if = "Option::is_none")]
		pub system: Option<Vec<SystemContentBlock>>,
		/// Inference parameters to pass to the model.
		#[serde(rename = "inferenceConfig", skip_serializing_if = "Option::is_none")]
		pub inference_config: Option<InferenceConfiguration>,
		/// Configuration information for the tools that the model can use.
		#[serde(rename = "toolConfig", skip_serializing_if = "Option::is_none")]
		pub tool_config: Option<ToolConfiguration>,
		/// Configuration information for a guardrail.
		#[serde(rename = "guardrailConfig", skip_serializing_if = "Option::is_none")]
		pub guardrail_config: Option<GuardrailConfiguration>,
		/// Additional model request fields.
		#[serde(
			rename = "additionalModelRequestFields",
			skip_serializing_if = "Option::is_none"
		)]
		pub additional_model_request_fields: Option<serde_json::Value>,
		/// Prompt variables.
		#[serde(rename = "promptVariables", skip_serializing_if = "Option::is_none")]
		pub prompt_variables: Option<HashMap<String, PromptVariableValues>>,
		/// Additional model response field paths.
		#[serde(
			rename = "additionalModelResponseFieldPaths",
			skip_serializing_if = "Option::is_none"
		)]
		pub additional_model_response_field_paths: Option<Vec<String>>,
		/// Request metadata.
		#[serde(rename = "requestMetadata", skip_serializing_if = "Option::is_none")]
		pub request_metadata: Option<HashMap<String, String>>,
		/// Performance configuration.
		#[serde(rename = "performanceConfig", skip_serializing_if = "Option::is_none")]
		pub performance_config: Option<PerformanceConfiguration>,
	}

	#[derive(Clone, Serialize, Debug)]
	pub struct ToolConfiguration {
		/// An array of tools that you want to pass to a model.
		pub tools: Vec<Tool>,
		/// If supported by model, forces the model to request a tool.
		pub tool_choice: Option<ToolChoice>,
	}

	#[derive(Clone, std::fmt::Debug, ::serde::Serialize)]
	#[serde(rename_all = "camelCase")]
	pub enum Tool {
		/// CachePoint to include in the tool configuration.
		CachePoint(CachePointBlock),
		/// The specification for the tool.
		ToolSpec(ToolSpecification),
	}

	#[derive(Clone, std::fmt::Debug, ::serde::Serialize, ::serde::Deserialize)]
	#[serde(rename_all = "camelCase")]
	pub struct CachePointBlock {
		/// Specifies the type of cache point within the CachePointBlock.
		pub r#type: CachePointType,
	}

	#[derive(
		Clone,
		Eq,
		Ord,
		PartialEq,
		PartialOrd,
		std::fmt::Debug,
		std::hash::Hash,
		::serde::Serialize,
		::serde::Deserialize,
	)]
	#[serde(rename_all = "camelCase")]
	pub enum CachePointType {
		Default,
	}

	#[derive(Clone, Serialize, Debug, PartialEq)]
	pub struct GuardrailConfiguration {
		/// The unique identifier of the guardrail
		#[serde(rename = "guardrailIdentifier")]
		pub guardrail_identifier: String,
		/// The version of the guardrail
		#[serde(rename = "guardrailVersion")]
		pub guardrail_version: String,
		/// Whether to enable trace output from the guardrail
		#[serde(rename = "trace", skip_serializing_if = "Option::is_none")]
		pub trace: Option<String>,
	}

	#[derive(Clone, Serialize, Debug, PartialEq)]
	pub struct PromptVariableValues {
		// TODO: Implement prompt variable values
	}

	#[derive(Clone, Serialize, Deserialize, Debug)]
	pub struct PerformanceConfiguration {
		// TODO: Implement performance configuration
	}

	/// The actual response from the Bedrock Converse API (matches AWS SDK ConverseOutput)
	#[derive(Debug, Deserialize, Clone)]
	pub struct ConverseResponse {
		/// The result from the call to Converse
		pub output: Option<ConverseOutput>,
		/// The reason why the model stopped generating output
		#[serde(rename = "stopReason")]
		pub stop_reason: StopReason,
		/// The total number of tokens used in the call to Converse
		pub usage: Option<TokenUsage>,
		/// Metrics for the call to Converse
		#[allow(dead_code)]
		pub metrics: Option<ConverseMetrics>,
		/// Additional fields in the response that are unique to the model
		#[allow(dead_code)]
		#[serde(rename = "additionalModelResponseFields")]
		pub additional_model_response_fields: Option<serde_json::Value>,
		/// A trace object that contains information about the Guardrail behavior
		pub trace: Option<ConverseTrace>,
		/// Model performance settings for the request
		#[serde(rename = "performanceConfig")]
		#[allow(dead_code)]
		pub performance_config: Option<PerformanceConfiguration>,
	}

	#[derive(Debug, Deserialize, Clone)]
	pub struct ConverseErrorResponse {
		pub message: String,
	}

	/// The actual content output from the model
	#[derive(Debug, Deserialize, Clone)]
	#[serde(rename_all = "camelCase")]
	pub enum ConverseOutput {
		Message(Message),
		#[serde(other)]
		Unknown,
	}

	/// Token usage information
	#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
	pub struct TokenUsage {
		/// The number of input tokens which were used
		#[serde(rename = "inputTokens")]
		pub input_tokens: usize,
		/// The number of output tokens which were used
		#[serde(rename = "outputTokens")]
		pub output_tokens: usize,
		/// The total number of tokens used
		#[serde(rename = "totalTokens")]
		pub total_tokens: usize,
		/// The number of input tokens read from cache (optional)
		#[serde(
			rename = "cacheReadInputTokens",
			skip_serializing_if = "Option::is_none"
		)]
		pub cache_read_input_tokens: Option<usize>,
		/// The number of input tokens written to cache (optional)
		#[serde(
			rename = "cacheWriteInputTokens",
			skip_serializing_if = "Option::is_none"
		)]
		pub cache_write_input_tokens: Option<usize>,
	}

	/// Metrics for the Converse call
	#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
	pub struct ConverseMetrics {
		/// Latency in milliseconds
		#[serde(rename = "latencyMs")]
		pub latency_ms: u64,
	}

	/// Trace information for Guardrail behavior
	#[derive(Clone, Debug, Serialize, Deserialize)]
	pub struct ConverseTrace {
		/// Guardrail trace information
		#[serde(rename = "guardrail", skip_serializing_if = "Option::is_none")]
		pub guardrail: Option<serde_json::Value>,
	}

	/// Reason for stopping the response generation.
	#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
	#[serde(rename_all = "snake_case")]
	pub enum StopReason {
		ContentFiltered,
		EndTurn,
		GuardrailIntervened,
		MaxTokens,
		StopSequence,
		ToolUse,
	}

	#[derive(Clone, Debug, Serialize)]
	#[serde(rename_all = "camelCase")]
	pub enum ToolChoice {
		/// The model must request at least one tool (no text is generated).
		Any,
		/// (Default). The Model automatically decides if a tool should be called or whether to generate text instead.
		Auto,
		/// The Model must request the specified tool. Only supported by Anthropic Claude 3 models.
		Tool { name: String },
		/// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
		/// An unknown enum variant
		///
		/// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
		/// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
		/// by the client. This can happen when the server adds new functionality, but the client has not been updated.
		/// To investigate this, consider turning on debug logging to print the raw HTTP response.
		#[non_exhaustive]
		Unknown,
	}

	#[derive(Clone, std::fmt::Debug, ::serde::Serialize)]
	#[serde(rename_all = "camelCase")]
	pub struct ToolSpecification {
		/// The name for the tool.
		pub name: String,
		/// The description for the tool.
		pub description: Option<String>,
		/// The input schema for the tool in JSON format.
		pub input_schema: Option<ToolInputSchema>,
	}

	#[derive(Clone, Debug, Serialize)]
	#[serde(rename_all = "camelCase")]
	pub enum ToolInputSchema {
		Json(serde_json::Value),
	}

	// This is NOT deserialized directly, see the associated method
	#[derive(Clone, Debug)]
	pub enum ConverseStreamOutput {
		/// The messages output content block delta.
		ContentBlockDelta(ContentBlockDeltaEvent),
		/// Start information for a content block.
		#[allow(unused)]
		ContentBlockStart(ContentBlockStartEvent),
		/// Stop information for a content block.
		#[allow(unused)]
		ContentBlockStop(ContentBlockStopEvent),
		/// Message start information.
		MessageStart(MessageStartEvent),
		/// Message stop information.
		MessageStop(MessageStopEvent),
		/// Metadata for the converse output stream.
		Metadata(ConverseStreamMetadataEvent),
	}

	impl ConverseStreamOutput {
		pub fn deserialize(m: aws_event_stream_parser::Message) -> anyhow::Result<Self> {
			let Some(v) = m
				.headers
				.headers
				.iter()
				.find(|h| h.key.as_str() == ":event-type")
				.and_then(|v| match &v.value {
					aws_event_stream_parser::HeaderValue::String(s) => Some(s.to_string()),
					_ => None,
				})
			else {
				anyhow::bail!("no event type header")
			};
			Ok(match v.as_str() {
				"contentBlockDelta" => ConverseStreamOutput::ContentBlockDelta(serde_json::from_slice::<
					ContentBlockDeltaEvent,
				>(&m.body)?),
				"contentBlockStart" => ConverseStreamOutput::ContentBlockStart(serde_json::from_slice::<
					ContentBlockStartEvent,
				>(&m.body)?),
				"contentBlockStop" => ConverseStreamOutput::ContentBlockStop(serde_json::from_slice::<
					ContentBlockStopEvent,
				>(&m.body)?),
				"messageStart" => {
					ConverseStreamOutput::MessageStart(serde_json::from_slice::<MessageStartEvent>(&m.body)?)
				},
				"messageStop" => {
					ConverseStreamOutput::MessageStop(serde_json::from_slice::<MessageStopEvent>(&m.body)?)
				},
				"metadata" => ConverseStreamOutput::Metadata(serde_json::from_slice::<
					ConverseStreamMetadataEvent,
				>(&m.body)?),
				m => anyhow::bail!("unexpected event type: {m}"),
			})
		}
	}

	#[derive(Clone, Debug, Deserialize)]
	#[serde(rename_all = "camelCase")]
	pub struct ContentBlockDeltaEvent {
		/// The delta for a content block delta event.
		pub delta: Option<ContentBlockDelta>,
		/// The block index for a content block delta event.
		#[allow(dead_code)]
		pub content_block_index: i32,
	}

	#[derive(Clone, Debug, Deserialize)]
	#[serde(rename_all = "camelCase")]
	#[allow(unused)]
	pub struct ContentBlockStartEvent {
		/// Start information about a content block start event.
		pub start: Option<ContentBlockStart>,
		/// The index for a content block start event.
		pub content_block_index: i32,
	}

	#[derive(Clone, Debug, Deserialize)]
	#[serde(rename_all = "camelCase")]
	#[allow(unused)]
	pub struct ContentBlockStopEvent {
		/// The index for a content block.
		pub content_block_index: i32,
	}

	#[derive(Clone, Debug, Deserialize)]
	#[serde(rename_all = "camelCase")]
	pub struct MessageStartEvent {
		/// The role for the message.
		pub role: Role,
	}

	#[derive(Clone, Debug, Deserialize)]
	#[serde(rename_all = "camelCase")]
	pub struct MessageStopEvent {
		/// The reason why the model stopped generating output.
		pub stop_reason: StopReason,
		/// The additional model response fields.
		#[allow(dead_code)]
		pub additional_model_response_fields: Option<serde_json::Value>,
	}

	#[derive(Clone, Debug, Deserialize)]
	#[serde(rename_all = "camelCase")]
	pub struct ConverseStreamMetadataEvent {
		/// Usage information for the conversation stream event.
		pub usage: Option<TokenUsage>,
		/// The metrics for the conversation stream metadata event.
		#[allow(dead_code)]
		pub metrics: Option<ConverseMetrics>,
		/// Model performance configuration metadata for the conversation stream event.
		#[allow(dead_code)]
		pub performance_config: Option<PerformanceConfiguration>,
	}

	#[derive(Clone, Debug, Deserialize)]
	#[serde(rename_all = "camelCase")]
	pub enum ContentBlockDelta {
		ReasoningContent(ReasoningContentBlockDelta),
		Text(String),
		ToolUse(#[allow(unused)] ToolUseBlockDelta),
	}

	#[derive(Clone, Debug, Deserialize)]
	#[serde(rename_all = "camelCase")]
	pub struct ToolUseBlockDelta {
		#[allow(unused)]
		pub input: String,
	}

	#[derive(Clone, Debug, Deserialize)]
	pub enum ReasoningContentBlockDelta {
		#[serde(rename = "redactedContent")]
		RedactedContent(#[allow(unused)] Bytes),
		#[serde(rename = "signature")]
		Signature(#[allow(unused)] String),
		#[serde(rename = "text")]
		Text(String),
		#[non_exhaustive]
		Unknown,
	}

	#[derive(Clone, Debug, Deserialize)]
	#[serde(rename_all = "camelCase")]
	pub enum ContentBlockStart {
		/// Information about a tool that the model is requesting to use.
		#[allow(dead_code)]
		ToolUse(ToolUseBlockStart),
		/// Reasoning/thinking content block start
		#[allow(dead_code)]
		ReasoningContent,
		/// Text content block start
		#[allow(dead_code)]
		Text,
	}

	#[derive(Clone, Debug, Deserialize)]
	#[serde(rename_all = "camelCase")]
	pub struct ToolUseBlockStart {
		/// The ID for the tool request.
		#[allow(dead_code)]
		pub tool_use_id: String,
		/// The name of the tool that the model is requesting to use.
		#[allow(dead_code)]
		pub name: String,
	}
}
