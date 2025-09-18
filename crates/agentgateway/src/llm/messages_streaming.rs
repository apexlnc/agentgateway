//! Direct Bedrock → Anthropic Messages API streaming implementation
//!
//! This module provides streaming response conversion from Bedrock event streams
//! to Anthropic Messages API Server-Sent Events (SSE) format, bypassing the
//! Universal adapter for streaming responses to achieve better compatibility.

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Instant;

use bytes::Bytes;
use pin_project_lite::pin_project;
use tokio_util::codec::Decoder;
use tracing::debug;

// External crates
use aws_event_stream_parser::EventStreamCodec;

use crate::http::Body;
use crate::llm::bedrock::types::{ConverseStreamOutput, ContentBlockDelta, StopReason};
use crate::llm::{AIError, LLMResponse};
use crate::telemetry::log::AsyncLog;
use crate::store::LLMResponsePolicies;

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
    pub signature: String,
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
    pub container: Option<serde_json::Value>,
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

    /// Accumulated usage information
    current_usage: Option<Usage>,
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
                if let Some(event) = self.handle_content_block_delta(delta_event, log)? {
                    events.push(event);
                }
            },

            ConverseStreamOutput::ContentBlockStop(stop_event) => {
                if let Some(event) = self.handle_content_block_stop(stop_event)? {
                    events.push(event);
                }
            },

            ConverseStreamOutput::MessageStop(stop_event) => {
                let event = self.handle_message_stop(stop_event)?;
                events.push(event);
            },

            ConverseStreamOutput::Metadata(metadata_event) => {
                if let Some(event) = self.handle_metadata(metadata_event)? {
                    events.push(event);
                }
            },

            // Error handling - convert to error events or log and continue
            ConverseStreamOutput::InternalServerException(error_event) => {
                events.push(StreamEvent::Error {
                    error: ErrorResponse {
                        error_type: "internal_server_exception".to_string(),
                        message: format!("Internal server error: {:?}", error_event),
                    },
                });
            },
            ConverseStreamOutput::ModelStreamErrorException(error_event) => {
                events.push(StreamEvent::Error {
                    error: ErrorResponse {
                        error_type: "model_stream_error_exception".to_string(),
                        message: format!("Model stream error: {:?}", error_event),
                    },
                });
            },
            ConverseStreamOutput::ServiceUnavailableException(error_event) => {
                events.push(StreamEvent::Error {
                    error: ErrorResponse {
                        error_type: "service_unavailable_exception".to_string(),
                        message: format!("Service unavailable: {:?}", error_event),
                    },
                });
            },
            ConverseStreamOutput::ThrottlingException(error_event) => {
                events.push(StreamEvent::Error {
                    error: ErrorResponse {
                        error_type: "throttling_exception".to_string(),
                        message: format!("Throttling error: {:?}", error_event),
                    },
                });
            },
            ConverseStreamOutput::ValidationException(error_event) => {
                events.push(StreamEvent::Error {
                    error: ErrorResponse {
                        error_type: "validation_exception".to_string(),
                        message: format!("Validation error: {:?}", error_event),
                    },
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
            container: None,
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
            crate::llm::bedrock::types::ContentBlockStart::ToolUse(tool_start) => {
                let metadata = ContentBlockMetadata {
                    block_type: ContentBlockType::ToolUse,
                };

                let content_block = ResponseContentBlock::ToolUse(ResponseToolUseBlock {
                    id: tool_start.tool_use_id,
                    name: tool_start.name,
                    input: serde_json::Value::Object(serde_json::Map::new()), // Empty initially
                });

                (content_block, metadata)
            },

            crate::llm::bedrock::types::ContentBlockStart::Text(_) => {
                let metadata = ContentBlockMetadata {
                    block_type: ContentBlockType::Text,
                };

                let content_block = ResponseContentBlock::Text(ResponseTextBlock {
                    text: String::new(),
                    citations: None,
                });

                (content_block, metadata)
            },

            crate::llm::bedrock::types::ContentBlockStart::Reasoning(_) => {
                let metadata = ContentBlockMetadata {
                    block_type: ContentBlockType::Reasoning,
                };

                let content_block = ResponseContentBlock::Thinking(ResponseThinkingBlock {
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
        delta_event: crate::llm::bedrock::types::ContentBlockDeltaEvent,
        log: &AsyncLog<LLMResponse>,
    ) -> Result<Option<StreamEvent>, AIError> {
        let index = delta_event.content_block_index as usize;

        // Mark first token seen for timing
        if !self.seen_first_token {
            self.seen_first_token = true;
            log.non_atomic_mutate(|r| {
                r.first_token = Some(Instant::now());
            });
        }

        let delta = match delta_event.delta {
            ContentBlockDelta::Text { text } => ContentDelta::TextDelta { text },

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

                // Return the partial JSON as input_json_delta
                ContentDelta::InputJsonDelta {
                    partial_json: tool_use.input,
                }
            },

            ContentBlockDelta::ReasoningContent(reasoning_delta) => {
                // Map reasoning content to thinking deltas
                match reasoning_delta {
                    crate::llm::bedrock::types::ReasoningContentBlockDelta::Text(text) => {
                        ContentDelta::ThinkingDelta { thinking: text }
                    },
                }
            },

            ContentBlockDelta::Citation(_citation_delta) => {
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
        stop_event: crate::llm::bedrock::types::ContentBlockStopEvent,
    ) -> Result<Option<StreamEvent>, AIError> {
        let index = stop_event.content_block_index as usize;

        // Clean up tool JSON buffer if present
        if let Some(metadata) = self.content_block_metadata.get(&index)
            && metadata.block_type == ContentBlockType::ToolUse
            && let Some(json_buffer) = self.tool_json_buffers.remove(&index)
        {
            // Update global counter when removing buffer
            GLOBAL_BUFFER_USAGE.fetch_sub(json_buffer.len(), Ordering::Relaxed);
            
            debug!("assembled tool input JSON (len={})", json_buffer.len());
        }

        // Clean up metadata
        self.content_block_metadata.remove(&index);

        Ok(Some(StreamEvent::ContentBlockStop { index }))
    }

    /// Handle Bedrock MessageStop → Anthropic message_stop
    fn handle_message_stop(
        &mut self,
        stop_event: crate::llm::bedrock::types::MessageStopEvent,
    ) -> Result<StreamEvent, AIError> {
        // Convert stop reason
        let stop_reason = translate_stop_reason_to_anthropic(stop_event.stop_reason);

        let delta = MessageDelta {
            stop_reason: Some(stop_reason),
            stop_sequence: None, // Bedrock doesn't provide matched sequence details
            usage: self.current_usage.clone(),
        };

        Ok(StreamEvent::MessageDelta { delta })
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
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
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

    /// Finalize the stream and return the final message_stop event
    pub fn finalize(&mut self) -> Result<StreamEvent, AIError> {
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
                        if let Ok(bedrock_event) = ConverseStreamOutput::deserialize(message) {
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

/// Translate Bedrock stop reasons to Anthropic stop reasons
fn translate_stop_reason_to_anthropic(stop_reason: StopReason) -> String {
    match stop_reason {
        StopReason::EndTurn => "end_turn".to_string(),
        StopReason::MaxTokens => "max_tokens".to_string(),  
        StopReason::StopSequence => "stop_sequence".to_string(),
        StopReason::ContentFiltered => "stop_sequence".to_string(), // Map to stop_sequence 
        StopReason::GuardrailIntervened => "stop_sequence".to_string(), // Map to stop_sequence
        StopReason::ToolUse => "tool_use".to_string(),
    }
}