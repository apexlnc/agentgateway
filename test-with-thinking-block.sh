#!/bin/bash

# Test with actual thinking block in assistant message
echo "=== Testing With Thinking Block in Assistant ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "Testing with preserved thinking block..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: claude-code-20250219,context-1m-2025-08-07,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14" \
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
        "content": "List files using bash"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "thinking",
            "thinking": "The user wants me to list files using bash. I should use the bash tool to execute the ls command."
          },
          {
            "type": "text",
            "text": "I'\''ll list the files for you using bash."
          },
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
  }' | head -30

echo -e "\n\n=== Thinking Block Test Complete ==="