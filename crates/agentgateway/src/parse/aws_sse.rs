use aws_event_stream_parser::{EventStreamCodec, Message};
use bytes::Bytes;
use serde::Serialize;
use tokio_sse_codec::{Event, Frame, SseEncoder};

use super::transform::parser as transform_parser;
use crate::*;

pub fn transform<O: Serialize>(
	b: http::Body,
	mut f: impl FnMut(Message) -> Option<O> + Send + 'static,
) -> http::Body {
	let decoder = EventStreamCodec;
	let encoder = SseEncoder::new();

	transform_parser(b, decoder, encoder, move |o| {
		let transformed = f(o)?;
		let json_bytes = serde_json::to_vec(&transformed).ok()?;
		Some(Frame::Event(Event::<Bytes> {
			data: Bytes::from(json_bytes),
			name: std::borrow::Cow::Borrowed(""),
			id: None,
		}))
	})
}

/// Transform AWS EventStream to SSE, allowing multiple output events per input event
pub fn transform_multi<O: Serialize>(
	b: http::Body,
	mut f: impl FnMut(Message) -> Vec<O> + Send + 'static,
) -> http::Body {
	let decoder = EventStreamCodec;
	let encoder = SseEncoder::new();

	// We need to buffer multiple events
	let mut pending_events = Vec::new();

	transform_parser(b, decoder, encoder, move |o| {
		// If we have pending events, return them first
		if !pending_events.is_empty() {
			return pending_events.remove(0);
		}

		// Get new events from the transformer
		let transformed_events = f(o);

		// Convert all events to SSE frames
		for event in transformed_events {
			if let Ok(json_bytes) = serde_json::to_vec(&event) {
				pending_events.push(Some(Frame::Event(Event::<Bytes> {
					data: Bytes::from(json_bytes),
					name: std::borrow::Cow::Borrowed(""),
					id: None,
				})));
			}
		}

		// Return the first event if any, or None
		if !pending_events.is_empty() {
			pending_events.remove(0)
		} else {
			None
		}
	})
}
