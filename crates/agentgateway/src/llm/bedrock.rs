use agent_core::prelude::Strng;
use agent_core::strng;
use async_openai::types::FinishReason;
use bytes::Bytes;
use chrono;
use itertools::Itertools;
use rand::Rng;
use tracing::trace;

use crate::http::Response;
use crate::llm::bedrock::types::{
	ContentBlock, ContentBlockDelta, ConverseErrorResponse, ConverseRequest, ConverseResponse,
	ConverseStreamOutput, StopReason,
};
use crate::llm::{AIError, BackendAdapter, LLMResponse, universal};
use crate::llm::messages_streaming::AnthropicStreamBody;
use crate::telemetry::log::AsyncLog;
use crate::*;

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

// Implement BackendAdapter trait for Provider
impl BackendAdapter for Provider {
	type BReq = ConverseRequest;
	type BResp = ConverseResponse; 
	type BStream = ConverseStreamOutput;

	/// Convert Universal request to Bedrock ConverseRequest format
	fn to_backend(&self, ureq: &universal::UniversalRequest) -> Result<Self::BReq, AIError> {
		// Use provider's model if configured, otherwise use request model
		let model = if let Some(provider_model) = &self.model {
			provider_model.to_string()
		} else {
			ureq.caps.model.clone()
		};
		
		Ok(translate_universal_request(ureq, self, &model))
	}
	
	/// Convert Bedrock ConverseResponse to Universal message format
	fn from_backend(&self, bresp: Self::BResp, model_id: &str) -> Result<universal::UniversalMessage, AIError> {
		let model = self.model.as_deref().unwrap_or(model_id);
		
		// Get the output content from the response
		let output = bresp.output.ok_or(AIError::IncompleteResponse)?;
		
		// Extract the message from the output
		let message = match output {
			types::ConverseOutput::Message { message: msg } => msg,
		};
		
		// Convert Bedrock content blocks to Universal blocks
		let mut blocks = Vec::new();
		for block in &message.content {
			match block {
				ContentBlock::Text(text) => {
					blocks.push(universal::ContentBlock::Text { text: text.clone() });
				},
				ContentBlock::Image(image_block) => {
					// Convert Bedrock image to Universal with DataRef
					let (data_ref, mime) = match &image_block.source {
						types::ImageSource::Bytes { data } => {
							let mime = match image_block.format {
								types::ImageFormat::Png => "image/png".to_string(),
								types::ImageFormat::Jpeg => "image/jpeg".to_string(),
								types::ImageFormat::Gif => "image/gif".to_string(),
								types::ImageFormat::Webp => "image/webp".to_string(),
							};
							(universal::DataRef::Base64(data.clone()), mime)
						},
						types::ImageSource::S3Location { s3_location } => {
							// Use the S3 URI directly
							let mime = match image_block.format {
								types::ImageFormat::Png => "image/png".to_string(),
								types::ImageFormat::Jpeg => "image/jpeg".to_string(),
								types::ImageFormat::Gif => "image/gif".to_string(),
								types::ImageFormat::Webp => "image/webp".to_string(),
							};
							(universal::DataRef::Uri(s3_location.uri.clone()), mime)
						},
					};
					blocks.push(universal::ContentBlock::Image {
						mime,
						data: data_ref,
					});
				},
				ContentBlock::ToolResult(tr) => {
					// Convert Bedrock ToolResult to lossless Universal format
					let content = tr.content
						.iter()
						.map(|content_block| match content_block {
							ContentBlock::Text(text) => {
								universal::ContentBlock::Text { text: text.clone() }
							},
							_ => {
								// Handle other content block types as needed
								universal::ContentBlock::Text { text: "Unsupported content type".to_string() }
							}
						})
						.collect();
					
					let status = tr.status.as_ref().map(|s| match s {
						types::ToolResultStatus::Success => universal::ToolResultStatus::Success,
						types::ToolResultStatus::Error => universal::ToolResultStatus::Error,
					});

					blocks.push(universal::ContentBlock::ToolResult {
						tool_use_id: tr.tool_use_id.clone(),
						content,
						status,
					});
				},
				ContentBlock::ToolUse(tu) => {
					blocks.push(universal::ContentBlock::ToolUse {
						id: tu.tool_use_id.clone(),
						name: tu.name.clone(),
						input: tu.input.clone(),
					});
				},
				ContentBlock::Document(_doc) => {
					// TODO: Implement document support
					// For now, skip document blocks
					continue;
				},
				ContentBlock::CachePoint(_) => {
					// Cache points are metadata, not content - skip them
					continue;
				},
				ContentBlock::ReasoningContent(_reasoning) => {
					// TODO: Implement reasoning content support
					// For now, skip reasoning blocks
					continue;
				},
			}
		}
		
		// Map Bedrock stop reason to Universal stop reason
		let stop_reason = match bresp.stop_reason {
			Some(StopReason::EndTurn) => universal::StopReason::EndTurn,
			Some(StopReason::MaxTokens) => universal::StopReason::MaxTokens,
			Some(StopReason::StopSequence) => universal::StopReason::StopSequence,
			Some(StopReason::ContentFiltered) => universal::StopReason::ContentFilter,
			Some(StopReason::GuardrailIntervened) => universal::StopReason::ContentFilter,
			Some(StopReason::ToolUse) => universal::StopReason::ToolUse,
			None => universal::StopReason::EndTurn, // Default if no stop reason provided
		};
		
		// Convert usage from Bedrock format to Universal format
		let usage = bresp.usage.map(|token_usage| universal::Usage {
			prompt_tokens: token_usage.input_tokens as u32,
			completion_tokens: token_usage.output_tokens as u32,
			total_tokens: token_usage.total_tokens as u32,
			prompt_tokens_details: None,
			completion_tokens_details: None,
		});
		
		// Generate a unique ID since it's not provided in the response
		let id = format!("bedrock-{}", chrono::Utc::now().timestamp_millis());
		
		Ok(universal::UniversalMessage {
			id,
			model: model.to_string(),
			role: universal::MessageRole::Assistant,
			blocks,
			usage,
			stop_reason: Some(stop_reason),
			vendor: None, // TODO: Add vendor-specific data if needed
		})
	}
	
	/// Convert Bedrock streaming events to Universal frames
	fn stream_map(&mut self, ev: Self::BStream) -> Result<Vec<universal::UFrame>, AIError> {
		let mut frames = Vec::new();
		
		match ev {
			ConverseStreamOutput::MessageStart(start) => {
				let role = match start.role {
					types::Role::Assistant => universal::MessageRole::Assistant,
					types::Role::User => universal::MessageRole::User,
				};
				// Generate a temporary ID for streaming
				let id = format!("bedrock-stream-{}", chrono::Utc::now().timestamp_millis());
				frames.push(universal::UFrame::MessageStart {
					id,
					model: self.model.as_deref().unwrap_or("unknown").to_string(),
					role,
				});
			},
			ConverseStreamOutput::ContentBlockStart(start) => {
				match &start.start {
					types::ContentBlockStart::ToolUse(tool_start) => {
						// Emit ToolUseStart frame for tool use
						frames.push(universal::UFrame::ToolUseStart {
							idx: start.content_block_index as usize,
							id: tool_start.tool_use_id.clone(),
							name: tool_start.name.clone(),
						});
					},
					_ => {
						// Default to text block for Text or Reasoning blocks
						frames.push(universal::UFrame::BlockStart {
							idx: start.content_block_index as usize,
							kind: universal::BlockKind::Text,
						});
					}
				}
			},
			ConverseStreamOutput::ContentBlockDelta(delta) => {
				if let ContentBlockDelta::Text { text } = &delta.delta {
					frames.push(universal::UFrame::Delta {
						idx: delta.content_block_index as usize,
						text: text.clone(),
					});
				}
				// TODO: Handle ToolUse deltas when they're added to ContentBlockDelta
			},
			ConverseStreamOutput::ContentBlockStop(stop) => {
				frames.push(universal::UFrame::BlockStop {
					idx: stop.content_block_index as usize,
				});
			},
			ConverseStreamOutput::MessageStop(stop) => {
				let stop_reason = match stop.stop_reason {
					StopReason::EndTurn => universal::StopReason::EndTurn,
					StopReason::MaxTokens => universal::StopReason::MaxTokens,
					StopReason::StopSequence => universal::StopReason::StopSequence,
					StopReason::ContentFiltered => universal::StopReason::ContentFilter,
					StopReason::GuardrailIntervened => universal::StopReason::ContentFilter,
					StopReason::ToolUse => universal::StopReason::ToolUse,
				};
				frames.push(universal::UFrame::MessageStop { stop_reason });
			},
			ConverseStreamOutput::Metadata(metadata) => {
				if let Some(usage) = metadata.usage {
					// Emit usage as MessageDelta before MessageStop (Anthropic requirement)
					frames.push(universal::UFrame::MessageDelta {
						usage: universal::Usage {
							prompt_tokens: usage.input_tokens as u32,
							completion_tokens: usage.output_tokens as u32,
							total_tokens: usage.total_tokens as u32,
							prompt_tokens_details: None,
							completion_tokens_details: None,
						},
					});
				}
			},
			ConverseStreamOutput::InternalServerException(_) => {
				// Skip error events in UFrame conversion
			},
			ConverseStreamOutput::ModelStreamErrorException(_) => {
				// Skip error events in UFrame conversion
			},
			ConverseStreamOutput::ServiceUnavailableException(_) => {
				// Skip error events in UFrame conversion
			},
			ConverseStreamOutput::ThrottlingException(_) => {
				// Skip error events in UFrame conversion
			},
			ConverseStreamOutput::ValidationException(_) => {
				// Skip error events in UFrame conversion
			},
		}
		
		Ok(frames)
	}
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

	pub async fn process_response(
		&self,
		model: &str,
		bytes: &Bytes,
	) -> Result<universal::Response, AIError> {
		let model = self.model.as_deref().unwrap_or(model);
		let resp =
			serde_json::from_slice::<ConverseResponse>(bytes).map_err(AIError::ResponseParsing)?;

		// Bedrock response doesn't contain the model, so we pass through the model from the request into the response
		translate_response(resp, model)
	}

	pub async fn process_error(
		&self,
		bytes: &Bytes,
	) -> Result<universal::ChatCompletionErrorResponse, AIError> {
		let resp =
			serde_json::from_slice::<ConverseErrorResponse>(bytes).map_err(AIError::ResponseParsing)?;
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
		let anthropic_body = AnthropicStreamBody::new(
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
							_ => None,
						}
					},
					ConverseStreamOutput::ContentBlockStart(_) => {
						// TODO support tool calls
						None
					},
					ConverseStreamOutput::ContentBlockStop(_) => {
						// No need to send anything here
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
									prompt_tokens: usage.input_tokens as u32,
									completion_tokens: usage.output_tokens as u32,
									total_tokens: usage.total_tokens as u32,
									prompt_tokens_details: None,
									completion_tokens_details: None,
								}),
							)
						} else {
							None
						}
					},
					ConverseStreamOutput::InternalServerException(error_event) => {
						// Return error - this will terminate the stream
						eprintln!("Bedrock internal server error: {:?}", error_event);
						None
					},
					ConverseStreamOutput::ModelStreamErrorException(error_event) => {
						// Return error - this will terminate the stream
						eprintln!("Bedrock model stream error: {:?}", error_event);
						None
					},
					ConverseStreamOutput::ServiceUnavailableException(error_event) => {
						// Return error - this will terminate the stream
						eprintln!("Bedrock service unavailable: {:?}", error_event);
						None
					},
					ConverseStreamOutput::ThrottlingException(error_event) => {
						// Return error - this will terminate the stream
						eprintln!("Bedrock throttling error: {:?}", error_event);
						None
					},
					ConverseStreamOutput::ValidationException(error_event) => {
						// Return error - this will terminate the stream
						eprintln!("Bedrock validation error: {:?}", error_event);
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
	// Get the output content from the response
	let output = resp.output.ok_or(AIError::IncompleteResponse)?;

	// Extract the message from the output
	let message = match output {
		types::ConverseOutput::Message { message: msg } => msg,
	};
	// Bedrock has a vec of possible content types, while openai allows 1 text content and many tool calls
	// Assume the bedrock response has only one text
	// Convert Bedrock content blocks to OpenAI message content
	let mut tool_calls: Vec<universal::MessageToolCall> = Vec::new();
	let mut content = None;
	for block in &message.content {
		match block {
			ContentBlock::Text(text) => {
				content = Some(text.clone());
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
			ContentBlock::ReasoningContent(_) => continue, // Skip reasoning content for now
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
			prompt_tokens: token_usage.input_tokens as u32,
			completion_tokens: token_usage.output_tokens as u32,
			total_tokens: token_usage.total_tokens as u32,

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

fn translate_stop_reason(resp: &StopReason) -> FinishReason {
	match resp {
		StopReason::EndTurn => universal::FinishReason::Stop,
		StopReason::MaxTokens => universal::FinishReason::Length,
		StopReason::StopSequence => universal::FinishReason::Stop,
		StopReason::ContentFiltered => universal::FinishReason::ContentFilter,
		StopReason::GuardrailIntervened => universal::FinishReason::ContentFilter,
		StopReason::ToolUse => universal::FinishReason::ToolCalls,
	}
}

pub(super) fn translate_universal_request(ureq: &universal::UniversalRequest, provider: &Provider, model: &str) -> ConverseRequest {
	// Convert system blocks to Bedrock system content blocks
	let system = if ureq.system.is_empty() {
		None
	} else {
		let system_text = ureq.system
			.iter()
			.filter_map(|block| match block {
				universal::ContentBlock::Text { text } => Some(text.clone()),
				_ => None, // Skip non-text system blocks for now
			})
			.collect::<Vec<String>>()
			.join("\n");
		
		if system_text.is_empty() {
			None
		} else {
			Some(vec![types::SystemContentBlock::Text(system_text)])
		}
	};

	// Convert Universal messages to Bedrock format
	let messages: Vec<types::Message> = ureq.messages
		.iter()
		.filter_map(|msg| {
			let role = match msg.role {
				universal::MessageRole::Assistant => types::Role::Assistant,
				universal::MessageRole::User => types::Role::User,
				universal::MessageRole::System => return None, // Skip system (handled above)
				universal::MessageRole::Tool => types::Role::User, // Tool messages become user
			};

			let content: Vec<ContentBlock> = msg.blocks
				.iter()
				.filter_map(|block| match block {
					universal::ContentBlock::Text { text } => {
						Some(ContentBlock::Text(text.clone()))
					},
					universal::ContentBlock::ToolUse { id, name, input } => {
						Some(ContentBlock::ToolUse(types::ToolUseBlock {
							tool_use_id: id.clone(),
							name: name.clone(),
							input: input.clone(),
						}))
					},
					universal::ContentBlock::ToolResult { tool_use_id, content, status } => {
						// Convert array of ContentBlocks to ToolResultContentBlocks
						let tool_content = content
							.iter()
							.filter_map(|block| match block {
								universal::ContentBlock::Text { text } => {
									Some(ContentBlock::Text(text.clone()))
								},
								_ => None, // Only text supported in tool results for now
							})
							.collect();
						
						let bedrock_status = status.as_ref().map(|s| match s {
							universal::ToolResultStatus::Success => types::ToolResultStatus::Success,
							universal::ToolResultStatus::Error => types::ToolResultStatus::Error,
						});

						Some(ContentBlock::ToolResult(types::ToolResultBlock {
							tool_use_id: tool_use_id.clone(),
							content: tool_content,
							status: bedrock_status,
						}))
					},
					universal::ContentBlock::Image { .. } => {
						// TODO: Handle images when needed
						None
					},
					universal::ContentBlock::Document { .. } => {
						// TODO: Handle documents when needed  
						None
					},
					universal::ContentBlock::Thinking { .. } => {
						// Skip thinking blocks (Anthropic-specific)
						None
					},
				})
				.collect();

			if !content.is_empty() {
				Some(types::Message { role, content })
			} else {
				None
			}
		})
		.collect();

	// Build inference configuration from caps
	let inference_config = types::InferenceConfiguration {
		max_tokens: Some(ureq.caps.max_tokens as i32),
		temperature: ureq.caps.temperature,
		top_p: ureq.caps.top_p,
		stop_sequences: Some(ureq.caps.stop_sequences.clone().unwrap_or_default()),
	};

	// Build guardrail configuration if specified
	let guardrail_config = if let (Some(identifier), Some(version)) =
		(&provider.guardrail_identifier, &provider.guardrail_version)
	{
		Some(types::GuardrailConfiguration {
			guardrail_identifier: identifier.to_string(),
			guardrail_version: version.to_string(),
			trace: Some(types::GuardrailTrace::Enabled),
		})
	} else {
		None
	};

	// Convert tools to Bedrock format
	let tool_config = ureq.tools.as_ref().map(|tools| {
		let bedrock_tools = tools
			.iter()
			.map(|tool| {
				let tool_spec = types::ToolSpecification {
					name: tool.name.clone(),
					description: tool.description.clone(),
					input_schema: Some(types::ToolInputSchema::Json(tool.input_schema.clone())),
				};
				types::Tool::ToolSpec(tool_spec)
			})
			.collect();

		types::ToolConfiguration {
			tools: bedrock_tools,
			tool_choice: None, // TODO: Add tool choice support
		}
	});

	ConverseRequest {
		model_id: model.to_string(),
		messages: Some(messages),
		system,
		inference_config: Some(inference_config),
		tool_config,
		guardrail_config,
		additional_model_request_fields: None,
		additional_model_response_field_paths: None,
		request_metadata: None, // TODO: Extract from vendor data if needed
		performance_config: None,
	}
}

// Keep old function for backward compatibility
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

	// Convert messages to Bedrock format
	let messages: Vec<types::Message> = req
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

	// Build inference configuration
	let inference_config = types::InferenceConfiguration {
		max_tokens: Some(universal::max_tokens(&req) as i32),
		temperature: req.temperature,
		top_p: req.top_p,
		stop_sequences: Some(universal::stop_sequence(&req)),
	};

	// Build guardrail configuration if specified
	let guardrail_config = if let (Some(identifier), Some(version)) =
		(&provider.guardrail_identifier, &provider.guardrail_version)
	{
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
			tool: types::ToolChoiceToolSpec { name: function.name },
		})),
		Some(universal::ToolChoiceOption::Auto) => Some(types::ToolChoice::Auto(types::AutoToolChoice {
			auto: serde_json::Value::Object(serde_json::Map::new()),
		})),
		Some(universal::ToolChoiceOption::Required) => Some(types::ToolChoice::Any(types::AnyToolChoice {
			any: serde_json::Value::Object(serde_json::Map::new()),
		})),
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
	ConverseRequest {
		model_id: req.model.unwrap_or_default(),
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
	pub role: ConversationRole,
	pub content: Vec<ContentBlock>,
}

/// Conversation roles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConversationRole {
	User,
	Assistant,
}

// Alias for backward compatibility with existing bedrock.rs code
pub type Role = ConversationRole;

/// CRITICAL: ContentBlock is a strict UNION type - exactly one variant must be set
/// Multiple variants will cause validation errors
/// FORMAT: Tuple variants to match AWS SDK serialization exactly
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// S3 location structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct S3Location {
	pub uri: String,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub bucket_owner: Option<String>,
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

/// Guardrail trace setting
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardrailTrace {
	Enabled,
	Disabled,
}

/// Guardrail configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardrailConfiguration {
	/// Guardrail identifier
	pub guardrail_identifier: String,

	/// Guardrail version
	pub guardrail_version: String,

	/// Enable trace output
	#[serde(skip_serializing_if = "Option::is_none")]
	pub trace: Option<GuardrailTrace>,
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
	ToolUse(ToolUseBlockStart),
	Text(String),      // Usually empty for text blocks
	Reasoning(String), // For reasoning blocks
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

	/// Reasoning content delta
	ReasoningContent(ReasoningContentBlockDelta),

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
	/// Text reasoning delta
	Text(String),
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
