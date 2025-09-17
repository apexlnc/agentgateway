//! Bedrock Converse API providers and utilities

pub mod anthropic;
pub mod common;
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
