#!/bin/bash

# Test what's actually being sent to Bedrock by checking debug logs
echo "=== Debug: Checking what gets sent to Bedrock ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

# Add debug headers and minimal payload
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "X-Debug: true" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 100,
    "messages": [
      {
        "role": "user",
        "content": "Just say hello"
      }
    ]
  }' | jq '.'

echo -e "\n=== Non-tool test complete ===\n"

# Now test with tool call
echo "=== Tool call test ==="
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "X-Debug: true" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 100,
    "messages": [
      {
        "role": "assistant",
        "content": [
          {
            "type": "tool_use",
            "id": "test_001",
            "name": "simple_test",
            "input": {"test": "value"}
          }
        ]
      },
      {
        "role": "user",
        "content": [
          {
            "type": "tool_result",
            "tool_use_id": "test_001",
            "content": "test result"
          }
        ]
      }
    ],
    "tools": [
      {
        "name": "simple_test",
        "description": "Simple test tool",
        "input_schema": {
          "type": "object",
          "properties": {
            "test": {"type": "string"}
          }
        }
      }
    ]
  }' | jq '.'

echo -e "\n=== Tool call test complete ===\n"