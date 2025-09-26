#!/bin/bash

# Test to diagnose Claude Code tool execution failure
echo "=== Claude Code Tool Execution Diagnosis ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "1. Testing without tools (should work fine)..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 100,
    "messages": [
      {
        "role": "user",
        "content": "Write a simple bash command to list files"
      }
    ]
  }' | jq '.'

echo -e "\n2. Testing first tool call (should work, stop with tool_use)..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 1000,
    "messages": [
      {
        "role": "user",
        "content": "List the files in the current directory"
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
  }' | jq '.'

echo -e "\n3. Testing tool result follow-up (the failing case)..."
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 1000,
    "messages": [
      {
        "role": "user",
        "content": "List the files in the current directory"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "text",
            "text": "I'\''ll list the files in the current directory for you."
          },
          {
            "type": "tool_use",
            "id": "toolu_123",
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
            "tool_use_id": "toolu_123",
            "content": "total 8\ndrwxr-xr-x 3 user user 4096 Jan 1 12:00 .\ndrwxr-xr-x 3 user user 4096 Jan 1 12:00 ..\n-rw-r--r-- 1 user user    0 Jan 1 12:00 test.txt"
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
  }' | jq '.'

echo -e "\n=== Diagnosis Complete ==="