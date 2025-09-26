#!/bin/bash

# Test thinking blocks in streaming responses
echo "=== Testing Thinking Streaming ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "Testing thinking stream (should show content_block_start for thinking)..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 1000,
    "stream": true,
    "thinking": {
      "type": "enabled",
      "budget_tokens": 500
    },
    "messages": [
      {
        "role": "user",
        "content": "Solve this step by step: What is 15 * 23?"
      }
    ]
  }' | head -20

echo -e "\n\n=== Thinking Stream Test Complete ==="