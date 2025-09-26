#!/bin/bash

# Test tool execution with thinking enabled
echo "=== Testing Tool Execution with Thinking ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "1. Testing tool call with thinking enabled (streaming)..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 1000,
    "stream": true,
    "thinking": {
      "type": "enabled",
      "budget_tokens": 1000
    },
    "messages": [
      {
        "role": "user",
        "content": "List the files in the current directory using bash"
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
  }'

echo -e "\n\n2. Testing follow-up with thinking and tool_result..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 1000,
    "stream": true,
    "thinking": {
      "type": "enabled",
      "budget_tokens": 1000
    },
    "messages": [
      {
        "role": "user",
        "content": "List the files in the current directory using bash"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "text",
            "text": "I'\''ll help you list the files in the current directory using bash."
          },
          {
            "type": "tool_use",
            "id": "toolu_thinking_test",
            "name": "bash",
            "input": {"command": "ls -la"}
          }
        ]
      },
      {
        "role": "user",
        "content": [
          {
            "type": "tool_result",
            "tool_use_id": "toolu_thinking_test",
            "content": "total 24\ndrwxr-xr-x 5 user user 4096 Jan 1 12:00 .\ndrwxr-xr-x 3 user user 4096 Jan 1 12:00 ..\n-rw-r--r-- 1 user user  123 Jan 1 12:00 file1.txt\n-rw-r--r-- 1 user user  456 Jan 1 12:00 file2.txt"
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
  }'

echo -e "\n\n=== Thinking Tool Flow Test Complete ==="