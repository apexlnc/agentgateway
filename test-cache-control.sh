#!/bin/bash

# Test Anthropic cache control functionality with tool calls
echo "=== Testing Cache Control with Tool Calls ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

# Test cache control on system prompt and tool definitions
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: prompt-caching-2024-07-31" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 100,
    "system": [
      {
        "type": "text",
        "text": "You are a helpful assistant with access to tools. This is a long system prompt that should be cached for performance optimization in production usage scenarios.",
        "cache_control": {"type": "ephemeral"}
      }
    ],
    "messages": [
      {
        "role": "user",
        "content": "What'\''s the weather in San Francisco?"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "text",
            "text": "I'\''ll check the weather in San Francisco for you."
          },
          {
            "type": "tool_use",
            "id": "weather_sf_001",
            "name": "get_weather",
            "input": {"location": "San Francisco", "unit": "fahrenheit"}
          }
        ]
      },
      {
        "role": "user",
        "content": [
          {
            "type": "tool_result",
            "tool_use_id": "weather_sf_001",
            "content": "San Francisco: 65°F, foggy, moderate winds",
            "cache_control": {"type": "ephemeral"}
          }
        ]
      },
      {
        "role": "user",
        "content": "Great, thanks!"
      }
    ],
    "tools": [
      {
        "name": "get_weather",
        "description": "Get current weather information for a location. This tool definition should be cached.",
        "input_schema": {
          "type": "object",
          "properties": {
            "location": {"type": "string", "description": "The city and state"},
            "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
          },
          "required": ["location"]
        },
        "cache_control": {"type": "ephemeral"}
      }
    ]
  }' | jq '.'

echo -e "\n=== Cache Control Test Complete ===\n"