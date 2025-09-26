#!/bin/bash

# Test script to verify thinking/reasoning configuration with deployed Bedrock endpoint
# Usage: ./test-thinking-deployed.sh [ENDPOINT_URL]

set -e

ENDPOINT=${1:-"http://localhost:8080"}

echo "=== Testing Thinking Configuration with Deployed Bedrock ==="
echo "Endpoint: $ENDPOINT"

# Test with Anthropic Messages API format (should trigger thinking)
echo ""
echo "--- Test 1: Native /v1/messages with thinking config ---"
curl -v -X POST $ENDPOINT/v1/messages \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "x-api-key: test-key" \
  -d '{
    "model": "claude-3-5-sonnet-v2@20241022",
    "max_tokens": 1000,
    "thinking": {
      "type": "enabled",
      "budget_tokens": 500
    },
    "stream": true,
    "messages": [
      {
        "role": "user",
        "content": "Think step by step about how to solve 2x + 3 = 11. Show your reasoning process."
      }
    ]
  }' 2>&1 | head -30

echo ""
echo "--- Test 2: OpenAI /v1/chat/completions with reasoning ---"
curl -v -X POST $ENDPOINT/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-key" \
  -d '{
    "model": "claude-3-5-sonnet-v2@20241022",
    "max_tokens": 1000,
    "reasoning": {
      "enabled": true,
      "max_tokens": 500
    },
    "stream": true,
    "messages": [
      {
        "role": "user",
        "content": "Think step by step about how to solve 2x + 3 = 11. Show your reasoning process."
      }
    ]
  }' 2>&1 | head -30

echo ""
echo "=== Test Complete ==="
echo "Look for in the server logs:"
echo "1. 'Bedrock: Found reasoning config' - confirms config is received"
echo "2. 'Bedrock: Enabling thinking with budget_tokens' - confirms config sent to Bedrock"
echo "3. 'Bedrock: Received reasoning ContentBlockStart' - confirms reasoning events received"
echo "4. 'Bedrock: Received reasoning ContentBlockDelta' - confirms thinking deltas received"
echo ""
echo "Look for in the response:"
echo "5. 'event: content_block_delta' with 'thinking_delta' - confirms SSE output"