#!/bin/bash

# Test the exact tool execution round-trip that Claude Code does
echo "=== Testing Tool Round-Trip Debug ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "Step 1: Initial request that should stop with tool_use..."
RESPONSE1=$(curl -s -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: claude-code-20250219,context-1m-2025-08-07,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14" \
  -d '{
    "model": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "max_tokens": 3000,
    "thinking": {
      "type": "enabled",
      "budget_tokens": 2000
    },
    "messages": [
      {
        "role": "user",
        "content": "List files in current directory using bash"
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
  }')

echo "$RESPONSE1" | jq '.'

# Extract tool_use_id and tool call from response
TOOL_USE_ID=$(echo "$RESPONSE1" | jq -r '.content[] | select(.type=="tool_use") | .id')
TOOL_COMMAND=$(echo "$RESPONSE1" | jq -r '.content[] | select(.type=="tool_use") | .input.command')

echo ""
echo "Extracted tool_use_id: $TOOL_USE_ID"
echo "Extracted command: $TOOL_COMMAND"

if [ "$TOOL_USE_ID" = "null" ] || [ -z "$TOOL_USE_ID" ]; then
    echo "ERROR: No tool_use found in response!"
    exit 1
fi

echo ""
echo "Step 2: Simulating tool execution..."
TOOL_OUTPUT="total 24
drwxr-xr-x 8 user user 4096 Jan 22 12:00 .
drwxr-xr-x 3 user user 4096 Jan 22 12:00 ..
-rw-r--r-- 1 user user  123 Jan 22 12:00 file1.txt
-rw-r--r-- 1 user user  456 Jan 22 12:00 file2.txt"

echo "Tool output: $TOOL_OUTPUT"

echo ""
echo "Step 3: Sending tool result back (this is where Claude Code fails)..."
RESPONSE2=$(curl -s -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: claude-code-20250219,context-1m-2025-08-07,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14" \
  -d "{
    \"model\": \"us.anthropic.claude-sonnet-4-20250514-v1:0\",
    \"max_tokens\": 3000,
    \"thinking\": {
      \"type\": \"enabled\",
      \"budget_tokens\": 2000
    },
    \"messages\": [
      {
        \"role\": \"user\",
        \"content\": \"List files in current directory using bash\"
      },
      {
        \"role\": \"assistant\",
        \"content\": [
          {
            \"type\": \"text\",
            \"text\": \"I'll list the files in the current directory for you.\"
          },
          {
            \"type\": \"tool_use\",
            \"id\": \"$TOOL_USE_ID\",
            \"name\": \"bash\",
            \"input\": {\"command\": \"$TOOL_COMMAND\"}
          }
        ]
      },
      {
        \"role\": \"user\",
        \"content\": [
          {
            \"type\": \"tool_result\",
            \"tool_use_id\": \"$TOOL_USE_ID\",
            \"content\": \"$TOOL_OUTPUT\"
          }
        ]
      }
    ],
    \"tools\": [
      {
        \"name\": \"bash\",
        \"description\": \"Execute bash commands\",
        \"input_schema\": {
          \"type\": \"object\",
          \"properties\": {
            \"command\": {\"type\": \"string\", \"description\": \"The bash command to execute\"}
          },
          \"required\": [\"command\"]
        }
      }
    ]
  }")

echo "Response from tool result:"
echo "$RESPONSE2" | jq '.'

echo ""
echo "=== Tool Round-Trip Debug Complete ==="