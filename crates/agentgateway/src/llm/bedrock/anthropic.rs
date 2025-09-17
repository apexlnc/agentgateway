//! Anthropic Messages API to Bedrock Converse translation provider

use agent_core::prelude::Strng;
use agent_core::strng;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Instant;
use tracing::{debug, instrument, warn};

// External crates
use aws_event_stream_parser::EventStreamCodec;
use pin_project_lite::pin_project;
use tokio_util::codec::Decoder;

/// Maximum size for accumulated tool JSON input (2MB - matches standard payload limits in codebase)
const MAX_TOOL_JSON_SIZE: usize = 2_097_152;

use super::{
	common,
	types::{
		self as bedrock, CachePointBlock, CachePointType, ContentBlock, ConverseErrorResponse,
		ConverseRequest, ConverseResponse,
	},
};
use crate::http::Response;
use crate::llm::messages::{
	self as anthropic, ContentDelta, MessagesRequest, MessagesResponse, RequestContentBlock,
	ResponseContentBlock, StreamEvent,
};
use crate::llm::{AIError, LLMResponse};
use crate::telemetry::log::AsyncLog;

/// Extracted Anthropic-specific headers
#[derive(Debug, Clone)]
pub struct AnthropicHeaders {
	/// anthropic-version header (required)
	pub anthropic_version: Option<String>,

	/// anthropic-beta headers (comma-separated features)
	pub anthropic_beta: Option<Vec<String>>,

	/// Conversation ID for tracking (extracted from custom headers or generated)
	pub conversation_id: Option<String>,
}

/// Provider configuration for direct Anthropic-to-Bedrock translation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Provider {
	/// Shared Bedrock configuration
	#[serde(flatten)]
	pub common: common::Common,
}

impl crate::llm::Provider for Provider {
	const NAME: Strng = strng::literal!("aws.bedrock");
}

impl Provider {
	/// Extract Anthropic headers from HTTP request headers
	pub fn extract_headers(headers: &HeaderMap) -> Result<AnthropicHeaders, AIError> {
		extract_anthropic_headers(headers)
	}

	/// Process Anthropic Messages API request directly (no universal format)
	#[instrument(
		skip(self, anthropic_request),
		fields(
			conversation_id = conversation_id.as_deref(),
			// GenAI semantic conventions will be recorded via trait
		)
	)]
	pub async fn process_request(
		&self,
		anthropic_request: MessagesRequest,
		conversation_id: Option<String>,
		anthropic_headers: &AnthropicHeaders,
	) -> Result<ConverseRequest, AIError> {
		let conversation_id =
			conversation_id.unwrap_or_else(|| format!("conv_{}", chrono::Utc::now().timestamp_millis()));

		debug!(
			conversation_id = %conversation_id,
			has_thinking = anthropic_request.thinking.is_some(),
			"Processing request with thinking blocks"
		);

		let mut anthropic_request = anthropic_request;
		if let Some(model_override) = &self.common.model {
			anthropic_request.model = model_override.to_string();
		}

		let bedrock_model_id = self.resolve_model_id(&anthropic_request.model)?;

		debug!(
				original_model = %anthropic_request.model,
				bedrock_model_id = %bedrock_model_id,
				"Model resolution completed"
		);

		// Set model ID once after resolution
		anthropic_request.model = bedrock_model_id.clone();

		let bedrock_request = translate_request(&anthropic_request, &self.common, anthropic_headers)?;

		Ok(bedrock_request)
	}

	/// Process Bedrock response back to Anthropic format
	#[instrument(skip(self, bytes, headers))]
	pub async fn process_response_direct(
		&self,
		model_id: &str,
		bytes: &Bytes,
		headers: &HeaderMap,
	) -> Result<MessagesResponse, AIError> {
		// Log raw response for debugging if UTF-8 valid
		match std::str::from_utf8(bytes) {
			Ok(s) => {
				tracing::debug!("Raw Bedrock response: {}", s);
			},
			Err(e) => {
				tracing::error!(
					"Invalid UTF-8 in Bedrock response at byte {}: {:?}",
					e.valid_up_to(),
					&bytes[..std::cmp::min(100, bytes.len())]
				);
				return Err(AIError::MissingField(
					format!("Invalid UTF-8 in response: {}", e).into(),
				));
			},
		};

		let bedrock_response: ConverseResponse =
			serde_json::from_slice(bytes).map_err(AIError::ResponseParsing)?;

		let anthropic_response = translate_response(bedrock_response, model_id, headers)?;

		Ok(anthropic_response)
	}

	/// Process Bedrock error response back to Anthropic format
	pub async fn process_error_direct(
		&self,
		status_code: StatusCode,
		bytes: &Bytes,
	) -> Result<anthropic::MessagesErrorResponse, AIError> {
		// CRITICAL: Log raw error response for debugging ValidationException
		let error_str = match std::str::from_utf8(bytes) {
			Ok(s) => s,
			Err(e) => {
				tracing::error!(
					"Invalid UTF-8 in Bedrock error response at byte {} (status {}): {:?}",
					e.valid_up_to(),
					status_code,
					&bytes[..std::cmp::min(100, bytes.len())]
				);
				return Err(AIError::MissingField(
					format!("Invalid UTF-8 in error response: {}", e).into(),
				));
			},
		};
		tracing::error!(
			"Raw Bedrock error response ({}): {}",
			status_code,
			error_str
		);

		let bedrock_error = match serde_json::from_slice::<ConverseErrorResponse>(bytes) {
			Ok(error) => error,
			Err(parse_err) => {
				// CRITICAL: Log the parsing failure with details
				tracing::error!(
					"Failed to parse Bedrock error as ConverseErrorResponse: {}",
					parse_err
				);

				let error_message = String::from_utf8_lossy(bytes).trim().to_string();
				let error_message = if error_message.is_empty() {
					format!("HTTP {} error", status_code.as_u16())
				} else {
					error_message
				};

				ConverseErrorResponse {
					message: error_message,
					error_type: None,
				}
			},
		};

		let error_type = extract_bedrock_error_type(status_code.as_u16(), Some(&bedrock_error));

		let anthropic_error = translate_error_response(bedrock_error, error_type.as_deref())?;

		Ok(anthropic_error)
	}

	/// Process streaming responses with direct Anthropic SSE output
	#[instrument(skip(self, resp))]
	pub async fn process_streaming(
		&self,
		log: AsyncLog<LLMResponse>,
		rate_limit: crate::store::LLMResponsePolicies,
		resp: Response,
		model_id: &str,
	) -> Response {
		// Extract message ID from AWS Request ID header if available, otherwise use random ID
		// Always prefix with msg_ for Anthropic client compatibility
		let message_id = resp
			.headers()
			.get(crate::http::x_headers::X_AMZN_REQUESTID)
			.and_then(|s| s.to_str().ok().map(|s| format!("msg_{}", s)))
			.unwrap_or_else(|| format!("msg_{:016x}", rand::random::<u64>()));

		let (parts, body) = resp.into_parts();
		let anthropic_body = AnthropicStreamBody::new(
			body,
			message_id,
			model_id.to_string(),
			log,
			Some(rate_limit),
		);
		let mut sse_response = Response::from_parts(parts, crate::http::Body::new(anthropic_body));
		let headers = sse_response.headers_mut();
		headers.insert(
			"content-type",
			HeaderValue::from_static("text/event-stream; charset=utf-8"),
		);
		headers.insert("cache-control", HeaderValue::from_static("no-cache"));
		headers.insert("connection", HeaderValue::from_static("keep-alive"));
		headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
		headers.remove("content-length");

		sse_response
	}

	/// Get the Bedrock host for this region
	pub fn get_host(&self) -> String {
		self.common.host().to_string()
	}

	/// Get the Bedrock path for the given model and streaming mode
	pub fn get_path_for_model(&self, model_id: &str, is_streaming: bool) -> String {
		self
			.common
			.converse_path(model_id, is_streaming)
			.to_string()
	}

	/// Get the resolved Bedrock model ID from an Anthropic model name
	pub fn resolve_model_id(&self, anthropic_model: &str) -> Result<String, AIError> {
		Ok(self.common.resolve_model_id(anthropic_model))
	}

	/// Build request headers for Bedrock API
	pub fn build_bedrock_headers(
		&self,
		_anthropic_headers: &AnthropicHeaders,
	) -> Result<HeaderMap, AIError> {
		let mut headers = HeaderMap::new();

		// Only include headers that Bedrock Converse API actually uses
		headers.insert("Content-Type", HeaderValue::from_static("application/json"));

		// Note: Bedrock doesn't use X-Anthropic-Version or X-Anthropic-Beta headers
		// Anthropic beta features must be passed via additionalModelRequestFields.anthropic_beta instead

		Ok(headers)
	}
}

/// Extract usage information from SSE data for metrics
#[allow(dead_code)]
fn extract_usage_from_sse(sse_data: &str) -> Result<Option<anthropic::Usage>, AIError> {
	// Look for message_delta events containing usage
	if let Some(data_start) = sse_data.find("data: ") {
		let json_str = &sse_data[data_start + 6..];
		if let Some(json_end) = json_str.find('\n') {
			let json_str = &json_str[..json_end];

			if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str)
				&& parsed.get("type").and_then(|t| t.as_str()) == Some("message_delta")
				&& let Some(delta) = parsed.get("delta")
				&& let Some(usage) = delta.get("usage")
			{
				return Ok(serde_json::from_value(usage.clone()).ok());
			}
		}
	}

	Ok(None)
}

/// Stream event processor that converts Bedrock events to Anthropic SSE format
struct BedrockStreamProcessor {
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

	/// Accumulated usage information
	current_usage: Option<anthropic::Usage>,
}

/// Metadata for tracking content blocks during streaming
#[derive(Debug, Clone)]
struct ContentBlockMetadata {
	pub block_type: ContentBlockType,
	#[allow(dead_code)]
	pub tool_use_id: Option<String>,
	#[allow(dead_code)]
	pub tool_name: Option<String>,
}

/// Types of content blocks we're tracking
#[derive(Debug, Clone, PartialEq)]
enum ContentBlockType {
	Text,
	ToolUse,
	Reasoning,
	#[allow(dead_code)]
	Citations,
}

impl BedrockStreamProcessor {
	/// Create a new stream processor
	fn new(message_id: String, model: String) -> Self {
		Self {
			message_id,
			model,
			tool_json_buffers: HashMap::new(),
			content_block_metadata: HashMap::new(),
			seen_first_token: false,
			current_usage: None,
		}
	}

	/// Process a Bedrock stream event and convert to Anthropic events
	/// Returns Vec because some Bedrock events may produce multiple Anthropic events
	fn process_event(
		&mut self,
		bedrock_event: super::types::ConverseStreamOutput,
		log: &AsyncLog<LLMResponse>,
	) -> Result<Vec<StreamEvent>, AIError> {
		use super::types as bedrock;
		let mut events = Vec::new();

		match bedrock_event {
			bedrock::ConverseStreamOutput::MessageStart(start_event) => {
				let event = self.handle_message_start(start_event)?;
				events.push(event);
			},

			bedrock::ConverseStreamOutput::ContentBlockStart(start_event) => {
				let event = self.handle_content_block_start(start_event)?;
				events.push(event);
			},

			bedrock::ConverseStreamOutput::ContentBlockDelta(delta_event) => {
				let _index = delta_event.content_block_index;

				if let Some(event) = self.handle_content_block_delta(delta_event, log)? {
					events.push(event);
				}
			},

			bedrock::ConverseStreamOutput::ContentBlockStop(stop_event) => {
				if let Some(event) = self.handle_content_block_stop(stop_event)? {
					events.push(event);
				}
			},

			bedrock::ConverseStreamOutput::MessageStop(stop_event) => {
				let event = self.handle_message_stop(stop_event)?;
				events.push(event);
			},

			bedrock::ConverseStreamOutput::Metadata(metadata_event) => {
				if let Some(event) = self.handle_metadata(metadata_event)? {
					events.push(event);
				}
			},

			// Error events - convert to Anthropic error format
			bedrock::ConverseStreamOutput::InternalServerException(error_event) => {
				let error_event =
					self.handle_stream_error("internal_server_error", &error_event.message)?;
				events.push(error_event);
			},

			bedrock::ConverseStreamOutput::ModelStreamErrorException(error_event) => {
				let error_event = self.handle_stream_error("model_error", &error_event.message)?;
				events.push(error_event);
			},

			bedrock::ConverseStreamOutput::ServiceUnavailableException(error_event) => {
				let error_event = self.handle_stream_error("service_unavailable", &error_event.message)?;
				events.push(error_event);
			},

			bedrock::ConverseStreamOutput::ThrottlingException(error_event) => {
				let error_event = self.handle_stream_error("rate_limit_error", &error_event.message)?;
				events.push(error_event);
			},

			bedrock::ConverseStreamOutput::ValidationException(error_event) => {
				let error_event =
					self.handle_stream_error("invalid_request_error", &error_event.message)?;
				events.push(error_event);
			},
		}

		Ok(events)
	}

	/// Handle Bedrock MessageStart → Anthropic message_start
	fn handle_message_start(
		&mut self,
		_start_event: super::types::MessageStartEvent,
	) -> Result<StreamEvent, AIError> {
		// Create initial message with empty content for message_start
		let message = anthropic::MessagesResponse {
			id: self.message_id.clone(),
			r#type: "message".to_string(),
			role: "assistant".to_string(),
			content: Vec::new(),
			model: self.model.clone(),
			stop_reason: None,
			stop_sequence: None,
			usage: anthropic::Usage {
				input_tokens: 0,
				output_tokens: 0,
				cache_creation_input_tokens: None,
				cache_read_input_tokens: None,
				cache_creation: None,
				server_tool_use: None,
				service_tier: None,
			},
			container: None,
		};

		Ok(StreamEvent::MessageStart { message })
	}

	/// Handle Bedrock ContentBlockStart → Anthropic content_block_start
	fn handle_content_block_start(
		&mut self,
		start_event: super::types::ContentBlockStartEvent,
	) -> Result<StreamEvent, AIError> {
		use super::types as bedrock;
		let index = start_event.content_block_index;

		let (content_block, metadata) = match start_event.start {
			bedrock::ContentBlockStart::ToolUse(tool_start) => {
				let metadata = ContentBlockMetadata {
					block_type: ContentBlockType::ToolUse,
					tool_use_id: Some(tool_start.tool_use_id.clone()),
					tool_name: Some(tool_start.name.clone()),
				};

				let content_block =
					anthropic::ResponseContentBlock::ToolUse(anthropic::ResponseToolUseBlock {
						id: tool_start.tool_use_id,
						name: tool_start.name,
						input: serde_json::Value::Object(serde_json::Map::new()), // Empty initially
					});

				(content_block, metadata)
			},

			bedrock::ContentBlockStart::Text(_) => {
				let metadata = ContentBlockMetadata {
					block_type: ContentBlockType::Text,
					tool_use_id: None,
					tool_name: None,
				};

				let content_block = anthropic::ResponseContentBlock::Text(anthropic::ResponseTextBlock {
					text: String::new(),
					citations: None,
				});

				(content_block, metadata)
			},

			bedrock::ContentBlockStart::Reasoning(_) => {
				let metadata = ContentBlockMetadata {
					block_type: ContentBlockType::Reasoning,
					tool_use_id: None,
					tool_name: None,
				};

				let content_block =
					anthropic::ResponseContentBlock::Thinking(anthropic::ResponseThinkingBlock {
						thinking: String::new(),
						signature: String::new(),
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
		delta_event: super::types::ContentBlockDeltaEvent,
		log: &AsyncLog<LLMResponse>,
	) -> Result<Option<StreamEvent>, AIError> {
		use super::types as bedrock;
		let index = delta_event.content_block_index;

		// Mark first token seen for timing - record immediately at processor level
		if !self.seen_first_token {
			self.seen_first_token = true;
			// Record timing here where it's race-free
			log.non_atomic_mutate(|r| {
				r.first_token = Some(Instant::now());
			});
		}

		let delta = match delta_event.delta {
			bedrock::ContentBlockDelta::Text { text } => ContentDelta::TextDelta { text },

			bedrock::ContentBlockDelta::ToolUse {
				tool_use: tool_delta,
			} => {
				// Accumulate partial JSON for tool inputs with bounds checking
				let json_buffer = self.tool_json_buffers.entry(index).or_default();

				// Check size limit to prevent memory exhaustion
				if json_buffer.len() + tool_delta.input.len() > MAX_TOOL_JSON_SIZE {
					self.tool_json_buffers.remove(&index);
					return Err(crate::llm::AIError::RequestTooLarge);
				}

				json_buffer.push_str(&tool_delta.input);

				// Return the partial JSON as input_json_delta
				ContentDelta::InputJsonDelta {
					partial_json: tool_delta.input,
				}
			},

			bedrock::ContentBlockDelta::ReasoningContent(reasoning_delta) => {
				// Map reasoning content to thinking deltas
				match reasoning_delta {
					bedrock::ReasoningContentBlockDelta::Text(text) => {
						ContentDelta::ThinkingDelta { thinking: text }
					},
				}
			},

			bedrock::ContentBlockDelta::Citation(_citation_delta) => {
				// Citations are typically accumulated and attached to text blocks
				// For now, we'll skip them in the streaming interface
				return Ok(None);
			},
		};
		Ok(Some(StreamEvent::ContentBlockDelta { index, delta }))
	}

	/// Handle Bedrock ContentBlockStop → Anthropic content_block_stop
	fn handle_content_block_stop(
		&mut self,
		stop_event: super::types::ContentBlockStopEvent,
	) -> Result<Option<StreamEvent>, AIError> {
		let index = stop_event.content_block_index;

		// Clean up tool JSON buffer if present - don't validate, just pass through
		if let Some(metadata) = self.content_block_metadata.get(&index)
			&& metadata.block_type == ContentBlockType::ToolUse
			&& let Some(_json_buffer) = self.tool_json_buffers.remove(&index)
		{
			// Drop JSON re-parse attempt; it's client concern.
			// If you want visibility, log the length at debug and move on.
			debug!("assembled tool input JSON (len={})", _json_buffer.len());
		}

		// Clean up metadata
		self.content_block_metadata.remove(&index);

		Ok(Some(StreamEvent::ContentBlockStop { index }))
	}

	/// Handle Bedrock MessageStop → Anthropic message_stop
	fn handle_message_stop(
		&mut self,
		stop_event: super::types::MessageStopEvent,
	) -> Result<StreamEvent, AIError> {
		use super::types as bedrock;

		// Convert stop reason
		let stop_reason = match stop_event.stop_reason {
			bedrock::StopReason::EndTurn => anthropic::StopReason::EndTurn,
			bedrock::StopReason::ToolUse => anthropic::StopReason::ToolUse,
			bedrock::StopReason::MaxTokens => anthropic::StopReason::MaxTokens,
			bedrock::StopReason::StopSequence => anthropic::StopReason::StopSequence,
			bedrock::StopReason::GuardrailIntervened => anthropic::StopReason::Refusal,
			bedrock::StopReason::ContentFiltered => anthropic::StopReason::Refusal,
		};

		let delta = anthropic::MessageDelta {
			stop_reason: Some(stop_reason),
			stop_sequence: None, // Bedrock doesn't provide matched sequence details
			usage: self.current_usage.clone(),
		};

		Ok(StreamEvent::MessageDelta { delta })
	}

	/// Handle Bedrock Metadata events
	fn handle_metadata(
		&mut self,
		metadata_event: super::types::ConverseStreamMetadataEvent,
	) -> Result<Option<StreamEvent>, AIError> {
		if let Some(bedrock_usage) = metadata_event.usage {
			let usage = anthropic::Usage {
				input_tokens: bedrock_usage.input_tokens,
				output_tokens: bedrock_usage.output_tokens,
				cache_creation_input_tokens: bedrock_usage.cache_write_input_tokens,
				cache_read_input_tokens: bedrock_usage.cache_read_input_tokens,
				cache_creation: None,
				server_tool_use: None,
				service_tier: None,
			};
			self.current_usage = Some(usage.clone());

			// Anthropic requires message_delta before message_stop; carry usage here.
			let delta = anthropic::MessageDelta {
				stop_reason: None,
				stop_sequence: None,
				usage: Some(usage),
			};
			return Ok(Some(StreamEvent::MessageDelta { delta }));
		}
		Ok(None)
	}

	/// Handle stream error events
	fn handle_stream_error(&self, error_type: &str, message: &str) -> Result<StreamEvent, AIError> {
		Ok(StreamEvent::Error {
			error: anthropic::ErrorResponse {
				error_type: error_type.to_string(),
				message: message.to_string(),
			},
		})
	}

	/// Finalize the stream and return the final message_stop event
	fn finalize(&mut self) -> Result<StreamEvent, AIError> {
		// Clean up any remaining buffers - no validation needed
		if !self.tool_json_buffers.is_empty() {
			debug!(
				"clearing {} tool JSON buffers at stream end",
				self.tool_json_buffers.len()
			);
			self.tool_json_buffers.clear();
		}

		Ok(StreamEvent::MessageStop)
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
		upstream: crate::http::Body,
		decoder: EventStreamCodec,
		decode_buffer: bytes::BytesMut,
		outbound_frames: VecDeque<Bytes>,
		processor: BedrockStreamProcessor,
		log: AsyncLog<LLMResponse>,
		rate_limit: Option<crate::store::LLMResponsePolicies>,
		finished: bool,
	}
}

impl AnthropicStreamBody {
	pub fn new(
		upstream: crate::http::Body,
		message_id: String,
		model: String,
		log: AsyncLog<LLMResponse>,
		rate_limit: Option<crate::store::LLMResponsePolicies>,
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
						// Process Bedrock event → 0..N Anthropic events (preserve state!)
						if let Ok(bedrock_event) = super::types::ConverseStreamOutput::deserialize(message) {
							match this.processor.process_event(bedrock_event, this.log) {
								Ok(anthropic_events) => {
									// Convert each Anthropic event to SSE frame and queue
									// Note: First token timing is now handled at processor level
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
						// Continue the loop to decode immediately (no wake_by_ref needed)
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

					match this.processor.finalize() {
						Ok(final_event) => {
							let sse_bytes = serialize_anthropic_event_to_sse(&final_event)
								.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
							return Poll::Ready(Some(Ok(http_body::Frame::data(sse_bytes))));
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

/// Extract Anthropic-specific headers from HTTP request
pub fn extract_anthropic_headers(headers: &HeaderMap) -> Result<AnthropicHeaders, AIError> {
	let anthropic_version = headers
		.get("anthropic-version")
		.and_then(|v| v.to_str().ok())
		.map(|s| s.to_string());

	let mut beta_features = Vec::new();
	for value in headers.get_all("anthropic-beta") {
		if let Ok(beta_str) = value.to_str() {
			// Split comma-separated beta features
			for feature in beta_str.split(',') {
				let trimmed = feature.trim();
				if !trimmed.is_empty() {
					beta_features.push(trimmed.to_string());
				}
			}
		}
	}

	let anthropic_beta = if beta_features.is_empty() {
		None
	} else {
		Some(beta_features)
	};

	let conversation_id = headers
		.get("x-conversation-id")
		.and_then(|v| v.to_str().ok())
		.map(|s| s.to_string());

	Ok(AnthropicHeaders {
		anthropic_version,
		anthropic_beta,
		conversation_id,
	})
}

/// Main translation function: Anthropic MessagesRequest → Bedrock ConverseRequest
#[tracing::instrument(skip_all, fields(model = %anthropic_request.model, max_tokens = anthropic_request.max_tokens))]
pub fn translate_request(
	anthropic_request: &MessagesRequest,
	common: &common::Common,
	anthropic_headers: &AnthropicHeaders,
) -> Result<ConverseRequest, AIError> {
	let model = &anthropic_request.model;
	let mut bedrock_request = ConverseRequest::new(model.clone());
	if !anthropic_request.messages.is_empty() {
		let messages = translate_messages(&anthropic_request.messages)?;
		bedrock_request = bedrock_request.with_messages(messages);
	}

	if let Some(system) = &anthropic_request.system {
		let system_blocks = translate_system_prompt(system.clone())?;
		bedrock_request = bedrock_request.with_system(system_blocks);
	}
	let inference_config = translate_inference_config(
		anthropic_request.max_tokens as i32,
		anthropic_request.temperature,
		anthropic_request.top_p,
		anthropic_request.top_k,
		anthropic_request.stop_sequences.clone(),
	)?;
	bedrock_request = bedrock_request.with_inference_config(inference_config);

	if let Some(tools) = &anthropic_request.tools {
		let (bedrock_tools, tool_choice) =
			translate_tools_and_choice(tools.clone(), anthropic_request.tool_choice.clone())?;
		bedrock_request = bedrock_request.with_tools(bedrock_tools, tool_choice);
	}

	if let (Some(identifier), Some(version)) =
		(&common.guardrail_identifier, &common.guardrail_version)
	{
		bedrock_request.guardrail_config = Some(bedrock::GuardrailConfiguration {
			guardrail_identifier: identifier.to_string(),
			guardrail_version: version.to_string(),
			trace: Some(bedrock::GuardrailTrace::Enabled),
		});
	}

	if let Some(metadata) = &anthropic_request.metadata {
		let mut request_metadata = HashMap::new();

		if let Some(user_id) = &metadata.user_id {
			request_metadata.insert("user_id".to_string(), user_id.clone());
		}

		for (key, value) in &metadata.additional {
			if let Ok(string_value) = serde_json::to_string(&value) {
				request_metadata.insert(key.clone(), string_value);
			}
		}

		if !request_metadata.is_empty() {
			bedrock_request.request_metadata = Some(request_metadata);
		}
	}

	let mut additional_fields = serde_json::Map::new();

	// Add client's anthropic-beta features for Bedrock
	if let Some(beta_features) = &anthropic_headers.anthropic_beta {
		additional_fields.insert(
			"anthropic_beta".to_string(),
			serde_json::Value::Array(
				beta_features
					.iter()
					.map(|s| serde_json::Value::String(s.clone()))
					.collect(),
			),
		);
	}

	if let Some(thinking) = &anthropic_request.thinking {
		let mut thinking_json = serde_json::json!({ "type": thinking.thinking_type });
		if let Some(budget) = thinking.budget_tokens {
			thinking_json["budget_tokens"] = serde_json::json!(budget);
		}
		debug!(
			"Added thinking configuration to additional model fields: {:?}",
			thinking_json
		);
		additional_fields.insert("thinking".to_string(), thinking_json);
	}

	if let Some(config_fields) = &common.additional_model_fields
		&& let Some(config_obj) = config_fields.as_object()
	{
		for (key, value) in config_obj {
			additional_fields.insert(key.clone(), value.clone());
		}
	}

	// Pass through additional fields - let Bedrock handle validation
	if !additional_fields.is_empty() {
		bedrock_request.additional_model_request_fields =
			Some(serde_json::Value::Object(additional_fields));
	}

	Ok(bedrock_request)
}

fn translate_messages(
	anthropic_messages: &[anthropic::InputMessage],
) -> Result<Vec<bedrock::Message>, AIError> {
	let mut bedrock_messages = Vec::new();

	for message in anthropic_messages {
		let bedrock_message = translate_message(message)?;
		bedrock_messages.push(bedrock_message);
	}

	Ok(bedrock_messages)
}

fn translate_message(
	anthropic_message: &anthropic::InputMessage,
) -> Result<bedrock::Message, AIError> {
	let role = match anthropic_message.role {
		anthropic::MessageRole::User => bedrock::ConversationRole::User,
		anthropic::MessageRole::Assistant => bedrock::ConversationRole::Assistant,
	};

	let content = translate_content_blocks(&anthropic_message.content.clone().to_blocks())?;

	Ok(bedrock::Message { role, content })
}

/// CRITICAL: Bedrock ContentBlock is a strict union - exactly one variant must be set
fn translate_content_blocks(
	anthropic_blocks: &[RequestContentBlock],
) -> Result<Vec<ContentBlock>, AIError> {
	let mut bedrock_blocks = Vec::new();

	for block in anthropic_blocks {
		let bedrock_block = translate_content_block(block)?;
		bedrock_blocks.push(bedrock_block);
	}

	Ok(bedrock_blocks)
}

/// Translate single Anthropic content block to Bedrock content block (direct passthrough)
#[tracing::instrument(skip_all, fields(block_type = ?std::mem::discriminant(anthropic_block)))]
fn translate_content_block(anthropic_block: &RequestContentBlock) -> Result<ContentBlock, AIError> {
	tracing::debug!(
		"Translating content block: {:?}",
		std::mem::discriminant(anthropic_block)
	);

	let block = translate_content_block_inner(anthropic_block)?;

	tracing::debug!(
		"Successfully translated content block to: {:?}",
		std::mem::discriminant(&block)
	);

	// Log serialized form for debugging
	if let Ok(json) = serde_json::to_string(&block) {
		tracing::debug!("ContentBlock serializes to: {}", json);
	}

	Ok(block)
}

/// Inner content block translation (can fail)
fn translate_content_block_inner(
	anthropic_block: &RequestContentBlock,
) -> Result<ContentBlock, AIError> {
	match anthropic_block {
		RequestContentBlock::Text(text_block) => {
			// Simple text content - most common case
			Ok(ContentBlock::Text(text_block.text.clone()))
		},

		RequestContentBlock::Image(image_block) => {
			let bedrock_image = translate_image_block(image_block)?;
			Ok(ContentBlock::Image(bedrock_image))
		},

		RequestContentBlock::Document(document_block) => {
			let bedrock_document = translate_document_block(document_block)?;
			Ok(ContentBlock::Document(bedrock_document))
		},

		RequestContentBlock::ToolUse(tool_use_block) => {
			let bedrock_tool_use = bedrock::ToolUseBlock {
				tool_use_id: tool_use_block.id.clone(),
				name: tool_use_block.name.clone(),
				input: tool_use_block.input.clone(),
			};
			Ok(ContentBlock::ToolUse(bedrock_tool_use))
		},

		RequestContentBlock::ToolResult(tool_result_block) => {
			let bedrock_tool_result = translate_tool_result_block(tool_result_block)?;
			Ok(ContentBlock::ToolResult(bedrock_tool_result))
		},

		RequestContentBlock::Thinking(thinking_block) => {
			// Map Anthropic thinking blocks to Bedrock reasoning content

			let reasoning_text = bedrock::ReasoningTextBlock {
				text: thinking_block.thinking.clone(),
				signature: Some(thinking_block.signature.clone()),
			};

			Ok(ContentBlock::ReasoningContent(
				bedrock::ReasoningContentBlock {
					reasoning_text: Some(reasoning_text),
					redacted_content: None,
				},
			))
		},

		RequestContentBlock::SearchResult(search_result_block) => {
			// Flatten to text as compatibility shim
			warn!("Search result content block flattened to text for bedrock_direct compatibility");
			let text_content = if search_result_block.content.is_empty() {
				format!("[SearchResult: {}]", search_result_block.title)
			} else {
				let content_texts: Vec<String> = search_result_block
					.content
					.iter()
					.map(|text_block| text_block.text.clone())
					.collect();
				format!("{}: {}", search_result_block.title, content_texts.join(" "))
			};
			Ok(ContentBlock::Text(text_content))
		},
	}
}

/// Translate Anthropic image block to Bedrock image block
fn translate_image_block(
	anthropic_image: &anthropic::RequestImageBlock,
) -> Result<bedrock::ImageBlock, AIError> {
	let (format, source) = match &anthropic_image.source {
		anthropic::ImageSource::Base64 { media_type, data } => {
			let format = match media_type.as_str() {
				"image/jpeg" => bedrock::ImageFormat::Jpeg,
				"image/png" => bedrock::ImageFormat::Png,
				"image/gif" => bedrock::ImageFormat::Gif,
				"image/webp" => bedrock::ImageFormat::Webp,
				// Graceful fallback - warn and default to JPEG for unknown formats
				_ => {
					warn!(
						"Unknown image format '{}' - defaulting to JPEG and letting Bedrock validate",
						media_type
					);
					bedrock::ImageFormat::Jpeg
				},
			};
			let source = bedrock::ImageSource::Bytes { data: data.clone() };
			(format, source)
		},

		anthropic::ImageSource::Url { url } => {
			// Convert to placeholder - let Bedrock emit the authentic error
			warn!(
				"Image URL '{}' converted to placeholder for Bedrock validation (no HTTP client available)",
				url
			);
			let format = bedrock::ImageFormat::Jpeg; // Default format for placeholder
			let placeholder_data = format!("URL_PLACEHOLDER:{}", url);
			let source = bedrock::ImageSource::Bytes {
				data: placeholder_data,
			};
			(format, source)
		},

		anthropic::ImageSource::File { file_id } => {
			// Convert to placeholder - let Bedrock emit the authentic error
			warn!(
				"Image file ID '{}' converted to placeholder for Bedrock validation",
				file_id
			);
			let format = bedrock::ImageFormat::Jpeg; // Default format for placeholder
			let placeholder_data = format!("FILE_ID_PLACEHOLDER:{}", file_id);
			let source = bedrock::ImageSource::Bytes {
				data: placeholder_data,
			};
			(format, source)
		},
	};

	Ok(bedrock::ImageBlock { format, source })
}

/// Translate Anthropic document block to Bedrock document block
fn translate_document_block(
	anthropic_doc: &anthropic::RequestDocumentBlock,
) -> Result<bedrock::DocumentBlock, AIError> {
	let (format, name, source) = match &anthropic_doc.source {
		anthropic::DocumentSource::Base64Pdf {
			media_type: _,
			data,
		} => {
			let format = bedrock::DocumentFormat::Pdf;
			let name = anthropic_doc
				.title
				.clone()
				.unwrap_or_else(|| "document.pdf".to_string());
			let source = bedrock::DocumentSource::Bytes { data: data.clone() };
			(format, name, source)
		},

		anthropic::DocumentSource::PlainText {
			media_type: _,
			data,
		} => {
			let format = bedrock::DocumentFormat::Txt;
			let name = anthropic_doc
				.title
				.clone()
				.unwrap_or_else(|| "document.txt".to_string());
			let source = bedrock::DocumentSource::Bytes { data: data.clone() };
			(format, name, source)
		},

		anthropic::DocumentSource::ContentBlock { content_blocks: _ } => {
			// Fail honestly - bedrock_direct doesn't support content block documents
			warn!(
				"Document ContentBlock sources not supported on bedrock_direct route - supply base64 PDF or plain text"
			);
			return Err(AIError::UnsupportedContent);
		},

		anthropic::DocumentSource::UrlPdf { url } => {
			// Convert to placeholder - let Bedrock emit the authentic error
			warn!(
				"Document URL '{}' converted to placeholder for Bedrock validation (no HTTP client available)",
				url
			);
			let format = bedrock::DocumentFormat::Pdf; // Default format for URL placeholder
			let name = "url_placeholder.pdf".to_string();
			let placeholder_data = format!("URL_PLACEHOLDER:{}", url);
			let source = bedrock::DocumentSource::Bytes {
				data: placeholder_data,
			};
			(format, name, source)
		},

		anthropic::DocumentSource::File { file_id } => {
			// Convert to placeholder - let Bedrock emit the authentic error
			warn!(
				"Document file ID '{}' converted to placeholder for Bedrock validation",
				file_id
			);
			let format = bedrock::DocumentFormat::Pdf; // Default format for placeholder
			let name = format!("file_id_placeholder_{}.pdf", file_id);
			let placeholder_data = format!("FILE_ID_PLACEHOLDER:{}", file_id);
			let source = bedrock::DocumentSource::Bytes {
				data: placeholder_data,
			};
			(format, name, source)
		},
	};

	// Convert format enum to string
	let format_str = match format {
		bedrock::DocumentFormat::Pdf => "pdf",
		bedrock::DocumentFormat::Csv => "csv",
		bedrock::DocumentFormat::Doc => "doc",
		bedrock::DocumentFormat::Docx => "docx",
		bedrock::DocumentFormat::Xls => "xls",
		bedrock::DocumentFormat::Xlsx => "xlsx",
		bedrock::DocumentFormat::Html => "html",
		bedrock::DocumentFormat::Txt => "txt",
		bedrock::DocumentFormat::Md => "md",
	};

	Ok(bedrock::DocumentBlock {
		name,
		source,
		format: Some(format_str.to_string()),
		citations: None,
		context: None,
	})
}

/// Translate Anthropic request content blocks to Bedrock ContentBlocks for tool results
fn translate_request_content_blocks_to_content_blocks(
	blocks: &[RequestContentBlock],
) -> Result<Vec<bedrock::ContentBlock>, AIError> {
	blocks.iter().map(translate_content_block).collect()
}

/// Translate arbitrary content (Unknown variant) to Bedrock ContentBlocks
fn translate_arbitrary_content_to_content_blocks(
	value: serde_json::Value,
) -> Result<Vec<bedrock::ContentBlock>, AIError> {
	match value {
		// Simple string content
		serde_json::Value::String(text) => Ok(vec![bedrock::ContentBlock::Text(text)]),
		// Array of content blocks
		serde_json::Value::Array(arr) => {
			arr
				.into_iter()
				.map(|item| {
					// First try to parse as known content block types
					if let Ok(block) = serde_json::from_value::<RequestContentBlock>(item.clone()) {
						// Use main translation function (fails honestly)
						translate_content_block(&block)
					} else if let serde_json::Value::String(text) = item {
						// Plain string - allow this
						Ok(bedrock::ContentBlock::Text(text))
					} else {
						// Complex structure - fail honestly
						warn!("Complex unknown content structures not supported on bedrock_direct route");
						Err(AIError::UnsupportedContent)
					}
				})
				.collect()
		},
		// Any other JSON structure
		_ => {
			if let Some(text) = value.as_str() {
				Ok(vec![bedrock::ContentBlock::Text(text.to_string())])
			} else {
				// Fail honestly for non-text content
				warn!("Non-text unknown content not supported on bedrock_direct route");
				Err(AIError::UnsupportedContent)
			}
		},
	}
}

/// Translate Anthropic tool result block to Bedrock tool result block
fn translate_tool_result_block(
	anthropic_result: &anthropic::RequestToolResultBlock,
) -> Result<bedrock::ToolResultBlock, AIError> {
	let content = match &anthropic_result.content {
		Some(anthropic::ToolResultContent::Text(text)) => {
			vec![bedrock::ContentBlock::Text(text.clone())]
		},
		Some(anthropic::ToolResultContent::Blocks(blocks)) => {
			translate_request_content_blocks_to_content_blocks(blocks)?
		},
		Some(anthropic::ToolResultContent::Unknown(value)) => {
			translate_arbitrary_content_to_content_blocks(value.clone())?
		},
		None => vec![], // Empty content
	};

	let status = match anthropic_result.is_error {
		Some(true) => Some(bedrock::ToolResultStatus::Error),
		Some(false) => Some(bedrock::ToolResultStatus::Success),
		None => None, // Let Bedrock infer
	};

	Ok(bedrock::ToolResultBlock {
		tool_use_id: anthropic_result.tool_use_id.clone(),
		content,
		status,
	})
}

/// Translate Anthropic system prompt to Bedrock system content blocks
fn translate_system_prompt(
	anthropic_system: anthropic::SystemPrompt,
) -> Result<Vec<bedrock::SystemContentBlock>, AIError> {
	match anthropic_system {
		anthropic::SystemPrompt::String(text) => Ok(vec![bedrock::SystemContentBlock::Text(text)]),

		anthropic::SystemPrompt::Blocks(blocks) => {
			// Convert text blocks to system content blocks, preserving client cache_control
			let mut system_blocks = Vec::new();

			for block in blocks {
				// Add the text content
				system_blocks.push(bedrock::SystemContentBlock::Text(block.text));

				// If client specified cache_control, add a cache point after this block
				if block.cache_control.is_some() {
					system_blocks.push(bedrock::SystemContentBlock::CachePoint(CachePointBlock {
						cache_type: CachePointType::Default,
					}));
					tracing::debug!("Added cache point per client cache_control specification");
				}
			}

			Ok(system_blocks)
		},
	}
}

fn translate_inference_config(
	max_tokens: i32,
	temperature: Option<f32>,
	top_p: Option<f32>,
	_top_k: Option<u32>, // Bedrock doesn't have top_k in inference config
	stop_sequences: Option<Vec<String>>,
) -> Result<bedrock::InferenceConfiguration, AIError> {
	Ok(bedrock::InferenceConfiguration {
		max_tokens: Some(max_tokens),
		temperature,
		top_p,
		stop_sequences,
	})
}

fn translate_tools_and_choice(
	anthropic_tools: Vec<anthropic::Tool>,
	anthropic_tool_choice: Option<anthropic::ToolChoice>,
) -> Result<(Vec<bedrock::Tool>, Option<bedrock::ToolChoice>), AIError> {
	// Handle ToolChoice::None - don't include any tools in the request
	if let Some(anthropic::ToolChoice::None) = anthropic_tool_choice {
		return Ok((Vec::new(), None));
	}

	// Translate tools and handle cache_control by adding cache points as separate array elements
	let mut bedrock_tools = Vec::new();

	for anthropic_tool in anthropic_tools {
		let has_cache_control = anthropic_tool.cache_control.is_some();

		// Translate the tool itself (without cache_control)
		let bedrock_tool = translate_tool(anthropic_tool)?;
		bedrock_tools.push(bedrock_tool);

		// If the tool had cache_control, add a separate cache point element
		if has_cache_control {
			let cache_point = bedrock::Tool::CachePoint(CachePointBlock {
				cache_type: CachePointType::Default,
			});
			bedrock_tools.push(cache_point);
			tracing::debug!("Added cache point after tool per client cache_control specification");
		}
	}

	// Translate tool choice
	let bedrock_tool_choice = anthropic_tool_choice.map(translate_tool_choice);

	Ok((bedrock_tools, bedrock_tool_choice))
}

/// Translate single Anthropic tool to Bedrock tool specification
fn translate_tool(anthropic_tool: anthropic::Tool) -> Result<bedrock::Tool, AIError> {
	let tool_spec = bedrock::ToolSpecification {
		name: anthropic_tool.name,
		description: anthropic_tool.description,
		input_schema: Some(bedrock::ToolInputSchema::Json(anthropic_tool.input_schema)),
	};

	// Note: cache_control is handled at the tools array level by translate_tools_and_choice()

	Ok(bedrock::Tool::ToolSpec(tool_spec))
}

/// Translate Anthropic tool choice to Bedrock tool choice
/// Note: ToolChoice::None is handled at a higher level and will not reach this function
fn translate_tool_choice(anthropic_choice: anthropic::ToolChoice) -> bedrock::ToolChoice {
	match anthropic_choice {
		anthropic::ToolChoice::Auto { .. } => {
			bedrock::ToolChoice::Auto(bedrock::AutoToolChoice {
				auto: serde_json::Value::Object(serde_json::Map::new()), // Empty object {}
			})
		},
		anthropic::ToolChoice::Any { .. } => {
			bedrock::ToolChoice::Any(bedrock::AnyToolChoice {
				any: serde_json::Value::Object(serde_json::Map::new()), // Empty object {}
			})
		},
		anthropic::ToolChoice::Tool { name, .. } => {
			bedrock::ToolChoice::Tool(bedrock::ToolChoiceSpecific {
				tool: bedrock::ToolChoiceToolSpec { name },
			})
		},
		anthropic::ToolChoice::None => {
			// This should never be reached as None is handled in translate_tools_and_choice
			unreachable!("ToolChoice::None should be handled at a higher level")
		},
	}
}

/// Implement From trait for cleaner enum conversion
impl From<bedrock::StopReason> for anthropic::StopReason {
	fn from(bedrock_stop_reason: bedrock::StopReason) -> Self {
		match bedrock_stop_reason {
			bedrock::StopReason::EndTurn => anthropic::StopReason::EndTurn,
			bedrock::StopReason::MaxTokens => anthropic::StopReason::MaxTokens,
			bedrock::StopReason::StopSequence => anthropic::StopReason::StopSequence,
			bedrock::StopReason::ToolUse => anthropic::StopReason::ToolUse,
			bedrock::StopReason::ContentFiltered => anthropic::StopReason::Refusal, // Map content filter to refusal
			bedrock::StopReason::GuardrailIntervened => anthropic::StopReason::Refusal, // Map guardrails to refusal
		}
	}
}

/// Legacy translation function for backward compatibility
fn translate_stop_reason(bedrock_stop_reason: bedrock::StopReason) -> anthropic::StopReason {
	bedrock_stop_reason.into()
}

/// Translate Bedrock usage to Anthropic usage
fn translate_usage(
	bedrock_usage: Option<bedrock::TokenUsage>,
) -> Result<anthropic::Usage, AIError> {
	match bedrock_usage {
		Some(usage) => Ok(anthropic::Usage {
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

/// Translate Bedrock response to Anthropic MessagesResponse
pub fn translate_response(
	bedrock_response: ConverseResponse,
	model_id: &str,
	headers: &HeaderMap,
) -> Result<MessagesResponse, AIError> {
	let output_message = match bedrock_response.output {
		Some(bedrock::ConverseOutput::Message { message }) => message,
		None => {
			return Err(AIError::MissingField(
				"output message in Bedrock response".into(),
			));
		},
	};

	// Translate content blocks
	let content = translate_response_content_blocks(output_message.content)?;

	// Translate stop reason
	let stop_reason = bedrock_response.stop_reason.map(translate_stop_reason);

	// Translate usage information
	let usage = translate_usage(bedrock_response.usage)?;

	// Extract response ID from AWS Request ID header if available, otherwise use random ID
	// Always prefix with msg_ for Anthropic client compatibility
	let id = headers
		.get(crate::http::x_headers::X_AMZN_REQUESTID)
		.and_then(|s| s.to_str().ok().map(|s| format!("msg_{}", s)))
		.unwrap_or_else(|| format!("msg_{:016x}", rand::random::<u64>()));

	let anthropic_response = MessagesResponse {
		id,
		r#type: "message".to_string(),
		role: "assistant".to_string(), // Always assistant for responses
		content,
		model: model_id.to_string(),
		stop_reason,
		stop_sequence: None, // Bedrock doesn't provide matched stop sequence details
		usage,
		container: None, // Bedrock doesn't provide container information
	};

	Ok(anthropic_response)
}

/// Translate Bedrock content blocks to Anthropic response content blocks
fn translate_response_content_blocks(
	bedrock_blocks: Vec<ContentBlock>,
) -> Result<Vec<ResponseContentBlock>, AIError> {
	bedrock_blocks
		.into_iter()
		.filter_map(|block| translate_response_content_block(block).transpose())
		.collect()
}

/// Translate single Bedrock content block to Anthropic response content block
fn translate_response_content_block(
	bedrock_block: ContentBlock,
) -> Result<Option<ResponseContentBlock>, AIError> {
	let anthropic_block = match bedrock_block {
		ContentBlock::Text(text) => {
			Some(ResponseContentBlock::Text(anthropic::ResponseTextBlock {
				text,
				citations: None, // Bedrock text doesn't include citation information
			}))
		},

		ContentBlock::ToolUse(tool_use) => Some(ResponseContentBlock::ToolUse(
			anthropic::ResponseToolUseBlock {
				id: tool_use.tool_use_id,
				name: tool_use.name,
				input: tool_use.input,
			},
		)),

		ContentBlock::ReasoningContent(reasoning_content) => {
			// Convert reasoning content to thinking blocks
			if let Some(reasoning_text) = reasoning_content.reasoning_text {
				Some(ResponseContentBlock::Thinking(
					anthropic::ResponseThinkingBlock {
						thinking: reasoning_text.text,
						signature: reasoning_text.signature.unwrap_or_default(),
					},
				))
			} else if reasoning_content.redacted_content.is_some() {
				// Handle redacted content - map to redacted thinking block
				Some(ResponseContentBlock::RedactedThinking(
					anthropic::ResponseRedactedThinkingBlock {
						data: reasoning_content.redacted_content.unwrap_or_default(),
					},
				))
			} else {
				None // Invalid reasoning block
			}
		},

		// Skip blocks that don't have direct Anthropic equivalents
		ContentBlock::Image { .. } => None, // Images in responses are rare
		ContentBlock::Document { .. } => None, // Documents in responses are rare
		ContentBlock::ToolResult { .. } => None, // Tool results shouldn't be in assistant responses
		ContentBlock::CachePoint { .. } => None, // Cache points are metadata, not content
	};

	Ok(anthropic_block)
}

/// Extract Bedrock error type from status code and error response
pub fn extract_bedrock_error_type(
	status_code: u16,
	error_response: Option<&super::types::ConverseErrorResponse>,
) -> Option<String> {
	// Map common HTTP status codes to Anthropic error types
	match status_code {
		400 => Some("invalid_request_error".to_string()),
		401 => Some("authentication_error".to_string()),
		403 => Some("permission_error".to_string()),
		404 => Some("not_found_error".to_string()),
		429 => Some("rate_limit_error".to_string()),
		500 => Some("api_error".to_string()),
		502..=504 => Some("api_error".to_string()),
		_ => {
			// Try to extract error type from Bedrock error response
			error_response.and_then(|e| e.error_type.as_ref()).map(|t| {
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
		},
	}
}

/// Translate Bedrock error response to Anthropic error response
pub fn translate_error_response(
	bedrock_error: super::types::ConverseErrorResponse,
	error_type: Option<&str>,
) -> Result<anthropic::MessagesErrorResponse, AIError> {
	let anthropic_error_type = error_type.unwrap_or("api_error").to_string();

	let anthropic_error = anthropic::ApiError {
		error_type: anthropic_error_type,
		message: bedrock_error.message,
	};

	Ok(anthropic::MessagesErrorResponse {
		response_type: "error".to_string(),
		error: anthropic_error,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_header_building() {
		let provider = Provider {
			common: common::Common {
				region: strng::new("us-east-1"),
				model: None,
				guardrail_identifier: None,
				guardrail_version: None,
				additional_model_fields: None,
				anthropic_beta: None,
				model_mappings: None,
				observability: Default::default(),
			},
		};

		let anthropic_headers = AnthropicHeaders {
			anthropic_version: Some("2023-06-01".to_string()),
			anthropic_beta: Some(vec!["files-api-2025-04-14".to_string()]),
			conversation_id: None,
		};

		let headers = provider.build_bedrock_headers(&anthropic_headers).unwrap();

		// Bedrock only needs Content-Type - no X-Anthropic headers
		assert!(headers.contains_key("Content-Type"));
		assert!(!headers.contains_key("X-Anthropic-Version"));
		assert!(!headers.contains_key("X-Anthropic-Beta"));
		assert_eq!(headers.len(), 1); // Only Content-Type
	}

	#[test]
	fn test_backward_compatibility_deserialization() {
		// Test that old bedrock config format can deserialize into new Provider
		let old_config_json = r#"{
            "region": "us-east-1",
            "model": "claude-3-sonnet-20240229",
            "guardrailIdentifier": "test-guardrail",
            "guardrailVersion": "1.0"
        }"#;

		let provider: Provider = serde_json::from_str(old_config_json).unwrap();

		// Verify core fields deserialize correctly
		assert_eq!(provider.common.region.as_str(), "us-east-1");
		assert_eq!(
			provider.common.model.as_deref().unwrap(),
			"claude-3-sonnet-20240229"
		);
		assert_eq!(
			provider
				.common
				.guardrail_identifier
				.as_ref()
				.unwrap()
				.as_str(),
			"test-guardrail"
		);
		assert_eq!(
			provider.common.guardrail_version.as_ref().unwrap().as_str(),
			"1.0"
		);
	}
}
