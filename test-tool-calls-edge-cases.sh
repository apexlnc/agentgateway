#!/bin/bash

# Test edge cases for tool call handling
echo "=== Testing Tool Call Edge Cases ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

echo "--- Test 1: Missing Tool Result (should create placeholder) ---"
curl -s -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 500,
    "messages": [
      {
        "role": "user",
        "content": "Test missing result"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "tool_use",
            "id": "toolu_missing_001",
            "name": "get_weather",
            "input": {"location": "Mars"}
          }
        ]
      },
      {
        "role": "user",
        "content": "Continue without tool result"
      }
    ],
    "tools": [
      {
        "name": "get_weather",
        "description": "Get weather",
        "input_schema": {
          "type": "object",
          "properties": {
            "location": {"type": "string"}
          },
          "required": ["location"]
        }
      }
    ]
  }' | jq '.'

echo -e "\n--- Test 2: Mismatched Tool IDs (should handle gracefully) ---"
curl -s -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 500,
    "messages": [
      {
        "role": "user",
        "content": "Test mismatched IDs"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "tool_use",
            "id": "toolu_expected_001",
            "name": "calculate",
            "input": {"expression": "1 + 1"}
          }
        ]
      },
      {
        "role": "user",
        "content": [
          {
            "type": "tool_result",
            "tool_use_id": "toolu_wrong_002",
            "content": "This ID does not match the tool_use ID"
          }
        ]
      },
      {
        "role": "user",
        "content": "Continue anyway"
      }
    ],
    "tools": [
      {
        "name": "calculate",
        "description": "Calculate",
        "input_schema": {
          "type": "object",
          "properties": {
            "expression": {"type": "string"}
          },
          "required": ["expression"]
        }
      }
    ]
  }' | jq '.'

echo -e "\n--- Test 3: Tool Results with Mixed Content ---"
curl -s -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 500,
    "messages": [
      {
        "role": "user",
        "content": "Mixed content test"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "tool_use",
            "id": "toolu_mixed_001",
            "name": "get_info",
            "input": {"query": "test"}
          }
        ]
      },
      {
        "role": "user",
        "content": [
          {
            "type": "text",
            "text": "Here'\''s some additional context before the tool result:"
          },
          {
            "type": "tool_result",
            "tool_use_id": "toolu_mixed_001",
            "content": "Tool result: Information retrieved successfully"
          },
          {
            "type": "text",
            "text": "And some text after the tool result."
          }
        ]
      },
      {
        "role": "user",
        "content": "Please summarize"
      }
    ],
    "tools": [
      {
        "name": "get_info",
        "description": "Get information",
        "input_schema": {
          "type": "object",
          "properties": {
            "query": {"type": "string"}
          },
          "required": ["query"]
        }
      }
    ]
  }' | jq '.'

echo -e "\n--- Test 4: Empty Tool Result ---"
curl -s -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 500,
    "messages": [
      {
        "role": "user",
        "content": "Empty result test"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "tool_use",
            "id": "toolu_empty_001",
            "name": "get_weather",
            "input": {"location": "Nowhere"}
          }
        ]
      },
      {
        "role": "user",
        "content": [
          {
            "type": "tool_result",
            "tool_use_id": "toolu_empty_001",
            "content": ""
          }
        ]
      },
      {
        "role": "user",
        "content": "What happened?"
      }
    ],
    "tools": [
      {
        "name": "get_weather",
        "description": "Get weather",
        "input_schema": {
          "type": "object",
          "properties": {
            "location": {"type": "string"}
          },
          "required": ["location"]
        }
      }
    ]
  }' | jq '.'

echo -e "\n=== Edge Cases Test Complete ===\n"