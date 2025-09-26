#!/bin/bash

# Test thinking blocks with a more complex problem
echo "=== Testing Detailed Thinking Stream ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "Testing thinking with complex reasoning task..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "max_tokens": 3000,
    "stream": true,
    "thinking": {
      "type": "enabled",
      "budget_tokens": 2000
    },
    "messages": [
      {
        "role": "user",
        "content": "I have a 5-liter jug and a 3-liter jug. How can I measure exactly 4 liters of water? Please think through this step by step."
      }
    ]
  }' | head -30

echo -e "\n\n=== Detailed Thinking Test Complete ==="