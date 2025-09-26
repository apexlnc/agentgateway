#!/bin/bash

# Test script to verify thinking/reasoning configuration with Bedrock
# This will help debug why thinking deltas aren't appearing in streaming

set -e

echo "=== Testing Thinking Configuration with Bedrock ==="

# Start the server in background if not running
if ! pgrep -f "agentgateway" > /dev/null; then
    echo "Starting agentgateway server..."
    RUST_LOG=debug ./target/debug/agentgateway serve --config config/gateway.toml &
    SERVER_PID=$!
    echo "Started server with PID: $SERVER_PID"
    sleep 3
else
    echo "Server already running"
    SERVER_PID=""
fi

# Test with Anthropic Messages API format (should trigger thinking)
echo ""
echo "--- Test 1: Native /v1/messages with thinking config ---"
curl -s -X POST http://localhost:8080/v1/messages \
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
  }' | head -20

echo ""
echo "--- Test 2: OpenAI /v1/chat/completions with reasoning ---"
curl -s -X POST http://localhost:8080/v1/chat/completions \
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
  }' | head -20

# Cleanup
if [ ! -z "$SERVER_PID" ]; then
    echo ""
    echo "Stopping server..."
    kill $SERVER_PID 2>/dev/null || true
fi

echo ""
echo "=== Test Complete ==="
echo "Check the logs above for:"
echo "1. 'Bedrock: Found reasoning config' - confirms config is received"
echo "2. 'Bedrock: Enabling thinking with budget_tokens' - confirms config sent to Bedrock"
echo "3. 'Bedrock: Received reasoning ContentBlockStart' - confirms reasoning events received"
echo "4. 'Bedrock: Received reasoning ContentBlockDelta' - confirms thinking deltas received"
echo "5. 'event: content_block_delta' with 'thinking_delta' - confirms SSE output"