#!/bin/bash

# Test thinking blocks without streaming
echo "=== Testing Thinking Non-Streaming ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "Testing thinking without streaming..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "max_tokens": 3000,
    "thinking": {
      "type": "enabled",
      "budget_tokens": 2000
    },
    "messages": [
      {
        "role": "user",
        "content": "Please think step by step: What is the best way to approach solving a complex math problem?"
      }
    ]
  }' | jq '.'

echo -e "\n\n=== Non-Streaming Thinking Test Complete ==="