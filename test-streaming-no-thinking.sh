#!/bin/bash

# Test streaming tool_result WITHOUT thinking to confirm hypothesis
echo "=== Testing Streaming Tool Result WITHOUT Thinking ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "Testing tool result with streaming (NO thinking)..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "max_tokens": 3000,
    "stream": true,
    "messages": [
      {
        "role": "user",
        "content": "List files using bash"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "tool_use",
            "id": "test_tool_123",
            "name": "bash",
            "input": {"command": "ls"}
          }
        ]
      },
      {
        "role": "user",
        "content": [
          {
            "type": "tool_result",
            "tool_use_id": "test_tool_123",
            "content": "file1.txt\nfile2.txt"
          }
        ]
      }
    ],
    "tools": [
      {
        "name": "bash",
        "description": "Execute bash commands",
        "input_schema": {
          "type": "object",
          "properties": {
            "command": {"type": "string"}
          },
          "required": ["command"]
        }
      }
    ]
  }' | head -10

echo -e "\n\n=== Streaming No-Thinking Test Complete ==="