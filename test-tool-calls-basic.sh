#!/bin/bash

# Test basic tool call handling with tool results
echo "=== Testing Basic Tool Call Handling ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

# Basic tool call test
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 1000,
    "messages": [
      {
        "role": "user",
        "content": "What'\''s the weather like in New York City?"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "text",
            "text": "I'\''ll check the weather in New York City for you."
          },
          {
            "type": "tool_use",
            "id": "toolu_01A09q90qw90lkasdjf",
            "name": "get_weather",
            "input": {"location": "New York City", "unit": "fahrenheit"}
          }
        ]
      },
      {
        "role": "user",
        "content": [
          {
            "type": "tool_result",
            "tool_use_id": "toolu_01A09q90qw90lkasdjf",
            "content": "The weather in New York City is currently 72°F and sunny with light winds."
          }
        ]
      },
      {
        "role": "user",
        "content": "Great! Can you summarize that?"
      }
    ],
    "tools": [
      {
        "name": "get_weather",
        "description": "Get current weather information for a location",
        "input_schema": {
          "type": "object",
          "properties": {
            "location": {"type": "string", "description": "The city and state"},
            "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
          },
          "required": ["location"]
        }
      }
    ]
  }' | jq '.'

echo -e "\n=== Basic Tool Call Test Complete ===\n"