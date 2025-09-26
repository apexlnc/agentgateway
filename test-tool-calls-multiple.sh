#!/bin/bash

# Test multiple tool calls with multiple tool results
echo "=== Testing Multiple Tool Calls Handling ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

# Multiple tool calls test
curl -X POST "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic.claude-3-sonnet-20240229-v1:0",
    "max_tokens": 1000,
    "messages": [
      {
        "role": "user",
        "content": "Can you check the weather in both New York and Los Angeles, and also calculate 15 + 27?"
      },
      {
        "role": "assistant",
        "content": [
          {
            "type": "text",
            "text": "I'\''ll check the weather in both cities and calculate that math for you."
          },
          {
            "type": "tool_use",
            "id": "toolu_weather_nyc_001",
            "name": "get_weather",
            "input": {"location": "New York City", "unit": "fahrenheit"}
          },
          {
            "type": "tool_use",
            "id": "toolu_weather_la_002",
            "name": "get_weather",
            "input": {"location": "Los Angeles", "unit": "fahrenheit"}
          },
          {
            "type": "tool_use",
            "id": "toolu_calc_003",
            "name": "calculate",
            "input": {"expression": "15 + 27"}
          }
        ]
      },
      {
        "role": "user",
        "content": [
          {
            "type": "tool_result",
            "tool_use_id": "toolu_weather_nyc_001",
            "content": "NYC: 72°F, sunny, light winds"
          },
          {
            "type": "tool_result",
            "tool_use_id": "toolu_weather_la_002",
            "content": "LA: 78°F, partly cloudy, gentle breeze"
          },
          {
            "type": "tool_result",
            "tool_use_id": "toolu_calc_003",
            "content": "42"
          }
        ]
      },
      {
        "role": "user",
        "content": "Perfect! Can you summarize all that information?"
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
      },
      {
        "name": "calculate",
        "description": "Perform mathematical calculations",
        "input_schema": {
          "type": "object",
          "properties": {
            "expression": {"type": "string", "description": "Mathematical expression to evaluate"}
          },
          "required": ["expression"]
        }
      }
    ]
  }' | jq '.'

echo -e "\n=== Multiple Tool Calls Test Complete ===\n"