#!/bin/bash

# Test concurrent tool call requests to check for race conditions
echo "=== Testing Concurrent Tool Call Requests ==="

GATEWAY_URL="https://kgateway.nydig-dev.cloud/bedrock/v1/messages"

# Function to run a single tool call request
run_request() {
  local request_id=$1
  echo "Starting request $request_id..."

  curl -s -X POST "$GATEWAY_URL" \
    -H "Content-Type: application/json" \
    -d '{
      "model": "anthropic.claude-3-sonnet-20240229-v1:0",
      "max_tokens": 500,
      "messages": [
        {
          "role": "user",
          "content": "Calculate the result of request '$request_id'"
        },
        {
          "role": "assistant",
          "content": [
            {
              "type": "text",
              "text": "I'\''ll calculate that for request '$request_id'."
            },
            {
              "type": "tool_use",
              "id": "toolu_req_'$request_id'_001",
              "name": "calculate",
              "input": {"expression": "'$request_id' * 10 + '$request_id'"}
            }
          ]
        },
        {
          "role": "user",
          "content": [
            {
              "type": "tool_result",
              "tool_use_id": "toolu_req_'$request_id'_001",
              "content": "Result for request '$request_id': '$(($request_id * 10 + $request_id))'"
            }
          ]
        },
        {
          "role": "user",
          "content": "Thanks!"
        }
      ],
      "tools": [
        {
          "name": "calculate",
          "description": "Perform mathematical calculations",
          "input_schema": {
            "type": "object",
            "properties": {
              "expression": {"type": "string", "description": "Mathematical expression"}
            },
            "required": ["expression"]
          }
        }
      ]
    }' > "/tmp/tool_test_result_$request_id.json" 2>&1

  if [ $? -eq 0 ]; then
    echo "Request $request_id completed successfully"
    # Check if response contains expected tool result handling
    if jq -e '.content // .choices[0].message.content' "/tmp/tool_test_result_$request_id.json" > /dev/null 2>&1; then
      echo "Request $request_id: Tool result properly processed ✓"
    else
      echo "Request $request_id: Tool result processing issue ✗"
      echo "Response:" && cat "/tmp/tool_test_result_$request_id.json"
    fi
  else
    echo "Request $request_id failed ✗"
    cat "/tmp/tool_test_result_$request_id.json"
  fi
}

# Run 10 concurrent requests
echo "Launching 10 concurrent tool call requests..."
for i in {1..10}; do
  run_request $i &
done

# Wait for all background jobs to complete
wait

echo -e "\n=== Checking Results ==="

# Count successful vs failed requests
success_count=0
fail_count=0

for i in {1..10}; do
  if [ -f "/tmp/tool_test_result_$i.json" ]; then
    if jq -e '.content // .choices[0].message.content' "/tmp/tool_test_result_$i.json" > /dev/null 2>&1; then
      ((success_count++))
    else
      ((fail_count++))
      echo "Failed request $i response:"
      cat "/tmp/tool_test_result_$i.json"
      echo "---"
    fi
  else
    ((fail_count++))
    echo "No response file for request $i"
  fi
done

echo "=== Concurrent Test Results ==="
echo "Successful requests: $success_count/10"
echo "Failed requests: $fail_count/10"

if [ $fail_count -eq 0 ]; then
  echo "✓ All concurrent tool call requests succeeded - no race conditions detected"
else
  echo "✗ Some requests failed - potential race conditions or other issues"
fi

# Cleanup
rm -f /tmp/tool_test_result_*.json

echo -e "\n=== Concurrent Tool Call Test Complete ===\n"