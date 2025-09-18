# Content Block Conversion Strategy: Messages -> Universal

## Overview

This document describes the comprehensive content block conversion strategy for transforming Anthropic Messages API format to Universal format (OpenAI-compatible). The implementation handles complex content block transformations while preserving vendor-specific data and ensuring compatibility across different AI providers.

## Architecture

### Core Principles

1. **Lossless Conversion**: All content is preserved, either in the main message or vendor-specific data
2. **Provider Compatibility**: Text fallbacks for providers that don't support advanced features
3. **Tool Pairing**: Maintains tool_use/tool_result relationships (partial implementation)
4. **Vendor Data Stashing**: Preserves image/document blocks for Bedrock egress
5. **Graceful Degradation**: Unsupported content types get meaningful text representations

### Message Structure Transformation

```
Messages API (Input)           Universal API (Output)
├── InputMessage              ├── RequestMessage
│   ├── role: user|assistant  │   ├── User|Assistant|Tool|System
│   └── content: String|Blocks│   └── content: String + tool_calls
│       ├── Text              │
│       ├── Image             │ → Stashed in vendor.bedrock.content_blocks
│       ├── Document          │ → Stashed in vendor.bedrock.content_blocks  
│       ├── ToolUse           │ → Assistant.tool_calls[]
│       ├── ToolResult        │ → Tool role message (future enhancement)
│       ├── Thinking          │ → vendor.thinking + text fallback
│       └── SearchResult      │ → vendor.search_results + extracted text
```

## Content Block Processing Pipeline

### 1. Text Block Concatenation

**Messages Input:**
```json
{
  "role": "user",
  "content": [
    {"type": "text", "text": "Hello"},
    {"type": "text", "text": "How are you?"}
  ]
}
```

**Universal Output:**
```json
{
  "role": "user", 
  "content": "Hello\n\nHow are you?"
}
```

**Rules:**
- Multiple text blocks are concatenated with `\n\n` separator
- Empty or whitespace-only blocks are filtered out
- Preserves original text content exactly

### 2. Tool Use Block Conversion

**Messages Input:**
```json
{
  "role": "assistant",
  "content": [
    {"type": "text", "text": "I'll search for that information."},
    {
      "type": "tool_use",
      "id": "call_123",
      "name": "search_web", 
      "input": {"query": "latest news"}
    }
  ]
}
```

**Universal Output:**
```json
{
  "role": "assistant",
  "content": "I'll search for that information.",
  "tool_calls": [
    {
      "id": "call_123",
      "type": "function",
      "function": {
        "name": "search_web",
        "arguments": "{\"query\":\"latest news\"}"
      }
    }
  ]
}
```

**Rules:**
- `tool_use.id` → `tool_calls[].id` (ID preservation)
- `tool_use.name` → `tool_calls[].function.name`
- `tool_use.input` → `tool_calls[].function.arguments` (JSON serialized)
- Text content and tool calls coexist in assistant messages

### 3. Tool Result Block Handling

**Current Implementation (Partial):**

**Messages Input:**
```json
{
  "role": "user",
  "content": [
    {"type": "text", "text": "Here's what I found:"},
    {
      "type": "tool_result",
      "tool_use_id": "call_123",
      "content": "Latest news articles...",
      "is_error": false
    }
  ]
}
```

**Current Universal Output:**
```json
{
  "role": "user",
  "content": "Here's what I found:\n\n[TOOL_RESULT:call_123] Latest news articles..."
}
```

**Future Enhancement (Planned):**
```json
[
  {
    "role": "user", 
    "content": "Here's what I found:"
  },
  {
    "role": "tool",
    "tool_call_id": "call_123", 
    "content": "Latest news articles..."
  }
]
```

**Rules:**
- Tool results are currently embedded in user message text with `[TOOL_RESULT:id]` prefix
- Error results get `ERROR:` prefix
- Future: Convert to separate Tool role messages with `tool_call_id`

### 4. Image/Document Block Stashing

**Messages Input:**
```json
{
  "role": "user",
  "content": [
    {"type": "text", "text": "Analyze this image:"},
    {
      "type": "image",
      "source": {
        "type": "base64",
        "media_type": "image/jpeg", 
        "data": "iVBORw0KGgoAAAANSUhEUgA..."
      }
    }
  ]
}
```

**Universal Output:**
```json
{
  "role": "user",
  "content": "Analyze this image:\n\n[IMAGE_ATTACHMENT]",
  "vendor": {
    "bedrock": {
      "content_blocks": [
        {
          "type": "image",
          "source": {
            "type": "base64", 
            "media_type": "image/jpeg",
            "data": "iVBORw0KGgoAAAANSUhEUgA..."
          }
        }
      ]
    }
  }
}
```

**Rules:**
- Original image/document blocks preserved in `vendor.bedrock.content_blocks`
- Text placeholders added: `[IMAGE_ATTACHMENT]`, `[DOCUMENT: title]`
- Enables Bedrock provider to reconstruct original format during egress

### 5. Thinking Block Preservation

**Messages Input:**
```json
{
  "role": "assistant",
  "content": [
    {
      "type": "thinking",
      "thinking": "Let me consider this carefully...",
      "signature": "sig_456"
    },
    {"type": "text", "text": "Based on my analysis..."}
  ]
}
```

**Universal Output:**
```json
{
  "role": "assistant",
  "content": "[THINKING] Let me consider this carefully...\n\nBased on my analysis...",
  "vendor": {
    "anthropic": {
      "thinking_blocks": [
        {
          "thinking": "Let me consider this carefully...", 
          "signature": "sig_456"
        }
      ]
    }
  }
}
```

**Rules:**
- Thinking content preserved in vendor data for compatible providers
- Text fallback `[THINKING] content` for other providers
- Maintains reasoning transparency where supported

### 6. Search Result Processing

**Messages Input:**
```json
{
  "role": "user",
  "content": [
    {
      "type": "search_result",
      "source": "web",
      "title": "AI News",
      "content": [
        {"type": "text", "text": "Recent developments in AI..."}
      ]
    }
  ]
}
```

**Universal Output:**
```json
{
  "role": "user",
  "content": "[SEARCH_RESULT: AI News]\nRecent developments in AI...",
  "vendor": {
    "anthropic": {
      "search_results": [
        {
          "source": "web",
          "title": "AI News",
          "content": [
            {"type": "text", "text": "Recent developments in AI..."}
          ]
        }
      ]
    }
  }
}
```

## Error Handling and Validation

### Content Validation
- Empty messages rejected with `MessageNotFound`
- Oversized content (>100KB) rejected with `RequestTooLarge`
- Invalid tool arguments cause `InvalidRequest` with serialization error

### Tool Pairing Validation (Future Enhancement)
```rust
// Planned validation logic
fn validate_tool_pairing(messages: &[Message]) -> Result<(), AIError> {
    let mut tool_uses = HashSet::new();
    let mut tool_results = HashSet::new();
    
    // Collect all tool_use and tool_result IDs
    // Ensure each tool_use has corresponding tool_result
    // Return validation errors for mismatched pairs
}
```

## Implementation Details

### Core Functions

1. **`to_universal()`**: Main conversion entry point
2. **`convert_input_message()`**: Handles individual message conversion
3. **`process_content_block()`**: Processes each content block type
4. **`ContentBlockConversionResult`**: Accumulates conversion results

### Data Structures

```rust
struct ContentBlockConversionResult {
    text_parts: Vec<String>,           // Accumulated text
    tool_calls: Vec<MessageToolCall>,  // Tool use conversions
    tool_results: HashMap<String, String>, // Tool result mappings
    vendor_data: VendorData,           // Provider-specific preservation
    validation_issues: Vec<String>,    // Processing warnings/errors
}

struct VendorData {
    bedrock_content_blocks: Vec<RequestContentBlock>, // Images/documents
    thinking_blocks: Vec<RequestThinkingBlock>,       // Thinking content  
    search_results: Vec<RequestSearchResultBlock>,   // Search results
}
```

## Current Limitations

### 1. Tool Result Messages
- **Current**: Tool results embedded in text with prefixes
- **Planned**: Separate Tool role messages with proper `tool_call_id` linking
- **Impact**: Tool results not properly structured for providers expecting separate messages

### 2. Multi-Message Output
- **Current**: One input message → one output message
- **Planned**: One input message → multiple output messages (for tool results)
- **Impact**: Requires restructuring conversion pipeline

### 3. Cross-Message Tool Validation
- **Current**: No validation of tool_use/tool_result pairing across messages
- **Planned**: Global tool pairing validation with detailed error reporting
- **Impact**: Invalid tool sequences may pass through undetected

### 4. Vendor Data Round-Trip
- **Current**: Stashing implemented, egress reconstruction pending
- **Planned**: Full round-trip preservation for image/document content
- **Impact**: Some content types may be lost in provider round-trips

## Usage Examples

### Basic Text Conversion
```rust
use agentgateway::llm::messages;

let request = MessagesRequest {
    model: "claude-sonnet-4".to_string(),
    max_tokens: 1000,
    messages: vec![
        InputMessage::user_text("Hello world".to_string())
    ],
    ..Default::default()
};

let universal = messages::to_universal(&request, &headers)?;
// Result: Single user message with text content
```

### Tool Use Conversion
```rust
let request = MessagesRequest {
    model: "claude-sonnet-4".to_string(), 
    max_tokens: 1000,
    messages: vec![
        InputMessage::assistant_blocks(vec![
            RequestContentBlock::Text(RequestTextBlock {
                text: "I'll search for that.".to_string(),
                ..Default::default()
            }),
            RequestContentBlock::ToolUse(Box::new(RequestToolUseBlock {
                id: "call_123".to_string(),
                name: "search".to_string(),
                input: json!({"query": "AI news"}),
                ..Default::default()
            }))
        ])
    ],
    ..Default::default()
};

let universal = messages::to_universal(&request, &headers)?;
// Result: Assistant message with content + tool_calls
```

### Mixed Content Conversion
```rust
let request = MessagesRequest {
    model: "claude-sonnet-4".to_string(),
    max_tokens: 1000, 
    messages: vec![
        InputMessage::user_blocks(vec![
            RequestContentBlock::Text(RequestTextBlock {
                text: "Analyze this:".to_string(),
                ..Default::default()
            }),
            RequestContentBlock::Image(Box::new(RequestImageBlock {
                source: ImageSource::Base64 {
                    media_type: "image/jpeg".to_string(),
                    data: "base64data...".to_string(),
                },
                ..Default::default()
            }))
        ])
    ],
    ..Default::default()
};

let universal = messages::to_universal(&request, &headers)?;
// Result: User message with "Analyze this:\n\n[IMAGE_ATTACHMENT]" 
//         + vendor.bedrock.content_blocks containing original image
```

## Future Enhancements

### Phase 2: Complete Tool Result Support
- Implement separate Tool role message generation
- Add cross-message tool pairing validation
- Support multiple output messages per input message

### Phase 3: Advanced Vendor Data
- Implement full round-trip preservation
- Add vendor-specific optimization hints
- Support provider-specific content transformations

### Phase 4: Streaming Support
- Extend conversion to streaming responses
- Maintain content block boundaries in streams
- Preserve vendor data in streaming context

## Testing Strategy

### Unit Tests
- Individual content block conversion functions
- Tool pairing validation logic
- Error handling for malformed content

### Integration Tests  
- End-to-end Messages → Universal → Provider conversion
- Round-trip fidelity testing
- Multi-provider compatibility validation

### Performance Tests
- Large message batch processing
- Memory usage with embedded images/documents
- Conversion latency benchmarks

---

This content block conversion strategy provides a robust foundation for Messages API compatibility while maintaining the flexibility to support diverse AI providers and content types.