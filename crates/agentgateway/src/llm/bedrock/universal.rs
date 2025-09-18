//! Universal Bedrock provider for OpenAI-style requests

use agent_core::prelude::Strng;
use agent_core::strng;
use async_openai::types::FinishReason;
use bytes::Bytes;
use chrono;
use itertools::Itertools;
use rand::Rng;
use std::collections::HashMap;
use std::time::Instant;
use tracing::{debug, trace, warn};

use super::{types, Common};
use crate::http::Response;
use crate::llm::{AIError, LLMResponse, universal};
use crate::telemetry::log::AsyncLog;

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// Universal Bedrock provider for OpenAI-style requests
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Provider {
	/// Shared Bedrock configuration
	#[serde(flatten)]
	pub common: Common,
}

impl crate::llm::Provider for Provider {
	const NAME: Strng = strng::literal!("aws.bedrock");
}

impl Provider {
	pub async fn process_request(
		&self,
		mut req: universal::Request,
	) -> Result<types::ConverseRequest, AIError> {
		if let Some(provider_model) = &self.common.model {
			req.model = Some(provider_model.to_string());
		} else if req.model.is_none() {
			return Err(AIError::MissingField("model not specified".into()));
		}
		let bedrock_request = translate_request(req, self);

		Ok(bedrock_request)
	}

	pub async fn process_response(
		&self,
		model: &str,
		bytes: &Bytes,
	) -> Result<universal::Response, AIError> {
		let model = self.common.model.as_deref().unwrap_or(model);
		let resp =
			serde_json::from_slice::<types::ConverseResponse>(bytes).map_err(AIError::ResponseParsing)?;

		translate_response(resp, model)
	}

	pub async fn process_error(
		&self,
		bytes: &Bytes,
	) -> Result<universal::ChatCompletionErrorResponse, AIError> {
		let resp = serde_json::from_slice::<types::ConverseErrorResponse>(bytes)
			.map_err(AIError::ResponseParsing)?;
		translate_error(resp)
	}

	pub async fn process_streaming(
		&self,
		log: AsyncLog<LLMResponse>,
		resp: Response,
		model: &str,
	) -> Response {
		let model = self.common.model.as_deref().unwrap_or(model).to_string();
		let message_id = resp
			.headers()
			.get(crate::http::x_headers::X_AMZN_REQUESTID)
			.and_then(|s| s.to_str().ok().map(|s| s.to_owned()))
			.unwrap_or_else(|| format!("{:016x}", rand::rng().random::<u64>()));
		let created = chrono::Utc::now().timestamp() as u32;
		resp.map(move |b| {
			let mut saw_token = false;
			crate::parse::aws_sse::transform::<universal::StreamResponse>(b, move |f| {
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
					types::ConverseStreamOutput::ContentBlockDelta(d) => {
						if !saw_token {
							saw_token = true;
							log.non_atomic_mutate(|r| {
								r.first_token = Some(Instant::now());
							});
						}

						match d.delta {
							types::ContentBlockDelta::Text { text } => {
								let choice = universal::ChatChoiceStream {
									index: 0,
									logprobs: None,
									delta: universal::StreamResponseDelta {
										role: None,
										content: Some(text),
										refusal: None,
										#[allow(deprecated)]
										function_call: None,
										tool_calls: None,
									},
									finish_reason: None,
								};
								mk(vec![choice], None)
							},
							other_delta => {
								// Unsupported delta type
								warn!(
									"Unsupported delta type in bedrock streaming: {:?}",
									other_delta
								);
								None
							},
						}
					},
					types::ConverseStreamOutput::ContentBlockStart(_start) => {
						// Content block start events not needed for universal format
						None
					},
					types::ConverseStreamOutput::ContentBlockStop(_stop) => {
						// No action needed for content block stop in universal format
						None
					},
					types::ConverseStreamOutput::MessageStart(start) => {
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
					types::ConverseStreamOutput::MessageStop(stop) => {
						let finish_reason = Some(translate_stop_reason(&stop.stop_reason));

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
					types::ConverseStreamOutput::Metadata(metadata) => {
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
					// Error events - log and skip
					types::ConverseStreamOutput::InternalServerException(_)
					| types::ConverseStreamOutput::ModelStreamErrorException(_)
					| types::ConverseStreamOutput::ServiceUnavailableException(_)
					| types::ConverseStreamOutput::ThrottlingException(_)
					| types::ConverseStreamOutput::ValidationException(_) => {
						// Error events cannot be converted to universal format - skip
						None
					},
				}
			})
		})
	}

	pub fn get_path_for_model(&self, streaming: bool, model: &str) -> Strng {
		let resolved_model = self.common.resolve_model_id(model);
		self.common.converse_path(&resolved_model, streaming)
	}

	pub fn get_host(&self) -> Strng {
		self.common.host()
	}
}

pub(super) fn translate_error(
	resp: types::ConverseErrorResponse,
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

pub fn translate_response(
	resp: types::ConverseResponse,
	model: &str,
) -> Result<universal::Response, AIError> {
	let output = resp.output.ok_or(AIError::IncompleteResponse)?;
	let message = match output {
		types::ConverseOutput::Message { message } => message,
	};
	let mut tool_calls: Vec<universal::MessageToolCall> = Vec::new();
	let mut content = None;
	for block in &message.content {
		match block {
			types::ContentBlock::Text(text) => {
				content = Some(text.clone());
			},
			types::ContentBlock::Image { .. } => continue, // Skip images in response for now
			types::ContentBlock::ToolResult(_) => {
				continue;
			},
			types::ContentBlock::ToolUse(tu) => {
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
			types::ContentBlock::Document(_)
			| types::ContentBlock::CachePoint(_)
			| types::ContentBlock::ReasoningContent(_) => {
				continue;
			},
		};
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
	};
	let finish_reason = resp.stop_reason.as_ref().map(translate_stop_reason);
	// Only one choice for Bedrock
	let choice = universal::ChatChoice {
		index: 0,
		message,
		finish_reason,
		logprobs: None,
	};
	let choices = vec![choice];

	// Convert usage from Bedrock format to OpenAI format
	let usage = if let Some(token_usage) = resp.usage {
		universal::Usage {
			prompt_tokens: token_usage.input_tokens,
			completion_tokens: token_usage.output_tokens,
			total_tokens: token_usage.total_tokens,

			prompt_tokens_details: None,
			completion_tokens_details: None,
		}
	} else {
		// Fallback if usage is not provided
		universal::Usage::default()
	};

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
		usage: Some(usage),
		service_tier: None,
		system_fingerprint: None,
	})
}

fn translate_stop_reason(resp: &types::StopReason) -> FinishReason {
	match resp {
		types::StopReason::EndTurn => universal::FinishReason::Stop,
		types::StopReason::MaxTokens => universal::FinishReason::Length,
		types::StopReason::StopSequence => universal::FinishReason::Stop,
		types::StopReason::ContentFiltered => universal::FinishReason::ContentFilter,
		types::StopReason::GuardrailIntervened => universal::FinishReason::ContentFilter,
		types::StopReason::ToolUse => universal::FinishReason::ToolCalls,
	}
}

pub fn translate_request(req: universal::Request, provider: &Provider) -> types::ConverseRequest {
	debug!(
		model = ?req.model,
		message_count = req.messages.len(),
		"Starting Bedrock request translation"
	);

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

	if !system.is_empty() {
		debug!(system_length = system.len(), "System prompt present");
	}

	let messages: Vec<_> = req
		.messages
		.iter()
		.filter(|msg| universal::message_role(msg) != universal::SYSTEM_ROLE)
		.filter_map(|msg| {
			let role = match universal::message_role(msg) {
				universal::ASSISTANT_ROLE => types::Role::Assistant,
				// Default to user for other roles
				_ => types::Role::User,
			};

			if let Some(text) = universal::message_text(msg) {
				Some(types::Message {
					role,
					content: vec![types::ContentBlock::Text(text.to_string())],
				})
			} else {
				warn!("Message has no text content, skipping");
				None
			}
		})
		.collect();

	let inference_config = types::InferenceConfiguration {
		max_tokens: Some(universal::max_tokens(&req) as i32),
		temperature: req.temperature,
		top_p: req.top_p,
		stop_sequences: Some(universal::stop_sequence(&req)),
	};

	// Build guardrail configuration if specified
	let guardrail_config = if let (Some(identifier), Some(version)) = (
		&provider.common.guardrail_identifier,
		&provider.common.guardrail_version,
	) {
		Some(types::GuardrailConfiguration {
			guardrail_identifier: identifier.to_string(),
			guardrail_version: version.to_string(),
			trace: Some(types::GuardrailTrace::Enabled),
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
		})) => Some(types::ToolChoice::Tool(types::ToolChoiceSpecific {
			tool: types::ToolChoiceToolSpec {
				name: function.name,
			},
		})),
		Some(universal::ToolChoiceOption::Auto) => {
			Some(types::ToolChoice::Auto(types::AutoToolChoice {
				auto: serde_json::Value::Object(serde_json::Map::new()),
			}))
		},
		Some(universal::ToolChoiceOption::Required) => {
			Some(types::ToolChoice::Any(types::AnyToolChoice {
				any: serde_json::Value::Object(serde_json::Map::new()),
			}))
		},
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

	types::ConverseRequest {
		model_id: req
			.model
			.clone()
			.expect("model guaranteed to be present after validation"),
		messages: Some(messages),
		system: if system.is_empty() {
			None
		} else {
			Some(vec![types::SystemContentBlock::Text(system)])
		},
		inference_config: Some(inference_config),
		tool_config,
		guardrail_config,
		additional_model_request_fields: None,
		additional_model_response_field_paths: None,
		request_metadata: metadata,
		performance_config: None,
	}
}
