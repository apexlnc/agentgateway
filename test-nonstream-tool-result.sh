#!/bin/bash

# Test non-streaming tool result to isolate the issue
echo "=== Testing Non-Streaming Tool Result ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "Testing non-streaming tool result..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "max_tokens": 3000,
    "messages": [
      {
        "role": "user",
        "content": "List files using bash"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "text",
            "text": "I will list the files for you."
          },
          {
            "type": "tool_use",
            "id": "tooluse_test123",
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
            "tool_use_id": "tooluse_test123",
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
  }' | jq '.'

echo -e "\n=== Non-Streaming Tool Result Test Complete ==="