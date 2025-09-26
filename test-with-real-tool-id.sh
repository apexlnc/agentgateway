#!/bin/bash

# Test with the real tool_use_id
echo "=== Testing With Real Tool Use ID ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "Testing tool result follow-up with real tool_use_id..."
curl -v -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: claude-code-20250219,context-1m-2025-08-07,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14" \
  -d '{
    "model": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "max_tokens": 10001,
    "stream": true,
    "thinking": {
      "type": "enabled",
      "budget_tokens": 2000
    },
    "messages": [
      {
        "role": "user",
        "content": "List files in current directory using bash"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "text",
            "text": "I'\''ll list the files in the current directory for you using the `ls` command."
          },
          {
            "type": "tool_use",
            "id": "tooluse_KIvYytVMRcW3gQ4SGJq6rw",
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
            "tool_use_id": "tooluse_KIvYytVMRcW3gQ4SGJq6rw",
            "content": "file1.txt\nfile2.txt\nfolder1\nfolder2"
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
            "command": {"type": "string", "description": "The bash command to execute"}
          },
          "required": ["command"]
        }
      }
    ]
  }' 2>&1 | head -50

echo -e "\n\n=== Real Tool ID Test Complete ==="