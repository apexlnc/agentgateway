#!/bin/bash

# Simple tool call debug test - minimal example
echo "=== Debug: Simple Tool Call ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

# Minimal test with just 1 tool_use and 1 tool_result
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
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

echo -e "\n=== Debug Test Complete ===\n"