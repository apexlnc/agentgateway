#!/bin/bash

# Test the exact flow Claude Code uses with error debugging
echo "=== Testing Exact Claude Code Flow with Error Debugging ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "Step 1: Initial request (this should work and return tool_use)..."
RESPONSE1=$(curl -s -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: claude-code-20250219,context-1m-2025-08-07,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14" \
  -H "anthropic-dangerous-direct-browser-access: true" \
  -H "user-agent: claude-cli/1.0.117 (external, sdk-cli)" \
  -H "x-app: cli" \
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
  }' 2>&1 | head -50)

echo "Initial response (first 50 lines):"
echo "$RESPONSE1"
echo ""

# Extract tool_use_id from the response if present
TOOL_USE_ID=$(echo "$RESPONSE1" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "Extracted tool_use_id: $TOOL_USE_ID"

if [ -z "$TOOL_USE_ID" ] || [ "$TOOL_USE_ID" = "" ]; then
    echo "ERROR: No tool_use_id found in initial response!"
    exit 1
fi

echo ""
echo "Step 2: Tool result follow-up (this is where the error likely occurs)..."

# Simulate what Claude Code sends back
RESPONSE2=$(curl -v -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: claude-code-20250219,context-1m-2025-08-07,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14" \
  -H "anthropic-dangerous-direct-browser-access: true" \
  -H "user-agent: claude-cli/1.0.117 (external, sdk-cli)" \
  -H "x-app: cli" \
  -d "{
    \"model\": \"us.anthropic.claude-sonnet-4-20250514-v1:0\",
    \"max_tokens\": 10001,
    \"stream\": true,
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
            \"text\": \"I'll list the files in the current directory for you using bash.\"
          },
          {
            \"type\": \"tool_use\",
            \"id\": \"$TOOL_USE_ID\",
            \"name\": \"bash\",
            \"input\": {\"command\": \"ls -la\"}
          }
        ]
      },
      {
        \"role\": \"user\",
        \"content\": [
          {
            \"type\": \"tool_result\",
            \"tool_use_id\": \"$TOOL_USE_ID\",
            \"content\": \"total 24\\ndrwxr-xr-x 8 user user 4096 Jan 22 12:00 .\\ndrwxr-xr-x 3 user user 4096 Jan 22 12:00 ..\\n-rw-r--r-- 1 user user  123 Jan 22 12:00 file1.txt\\n-rw-r--r-- 1 user user  456 Jan 22 12:00 file2.txt\"
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
  }" 2>&1)

echo "Tool result follow-up response:"
echo "$RESPONSE2"

echo ""
echo "=== Claude Code Flow Test Complete ==="