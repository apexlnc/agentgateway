#!/bin/bash

# Test cache control with correct beta header
echo "=== Testing Cache Control (Simple) ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

# Test with correct beta header format
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: prompt-caching-2024-07-31" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 100,
    "system": [
      {
        "type": "text",
        "text": "You are a helpful assistant. This system message has cache control enabled.",
        "cache_control": {"type": "ephemeral"}
      }
    ],
    "messages": [
      {
        "role": "user",
        "content": "Hello, how are you?"
      }
    ]
  }' | jq '.'

echo -e "\n=== Simple Cache Control Test Complete ===\n"

# Test without cache control for comparison
echo "=== Testing WITHOUT Cache Control (Baseline) ==="
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 100,
    "messages": [
      {
        "role": "user",
        "content": "Hello, how are you?"
      }
    ]
  }' | jq '.usage'

echo -e "\n=== Baseline Test Complete ===\n"