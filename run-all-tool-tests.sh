#!/bin/bash

# Comprehensive tool call testing suite
echo "========================================"
echo "    TOOL CALL TESTING SUITE"
echo "========================================"
echo "Testing against: kgateway.nydig-dev.cloud/bedrock"
echo "Endpoint: /v1/messages"
echo "Date: $(date)"
echo "========================================"

# Make all test scripts executable
chmod +x test-tool-calls-*.sh

# Initialize results tracking
declare -A test_results
total_tests=0
passed_tests=0

# Function to run a test and capture results
run_test() {
  local test_name="$1"
  local test_script="$2"

  echo -e "\n🔄 Running: $test_name"
  echo "----------------------------------------"

  ((total_tests++))

  if ./"$test_script"; then
    echo "✅ $test_name: PASSED"
    test_results["$test_name"]="PASSED"
    ((passed_tests++))
  else
    echo "❌ $test_name: FAILED"
    test_results["$test_name"]="FAILED"
  fi

  echo "----------------------------------------"
  sleep 2  # Brief pause between tests
}

# Run all test suites
echo -e "\n🚀 Starting Tool Call Test Suite...\n"

run_test "Basic Tool Call Test" "test-tool-calls-basic.sh"
run_test "Multiple Tool Calls Test" "test-tool-calls-multiple.sh"
run_test "Edge Cases Test" "test-tool-calls-edge-cases.sh"
run_test "Concurrent Requests Test" "test-tool-calls-concurrent.sh"

# Generate final report
echo -e "\n========================================"
echo "           FINAL REPORT"
echo "========================================"
echo "Total Tests: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $((total_tests - passed_tests))"
echo "Success Rate: $(( (passed_tests * 100) / total_tests ))%"
echo "========================================"

echo -e "\nDetailed Results:"
for test in "${!test_results[@]}"; do
  result="${test_results[$test]}"
  if [ "$result" = "PASSED" ]; then
    echo "  ✅ $test"
  else
    echo "  ❌ $test"
  fi
done

echo -e "\n========================================"

if [ $passed_tests -eq $total_tests ]; then
  echo "🎉 ALL TESTS PASSED!"
  echo "Tool aggregation fix appears to be working correctly."
  exit 0
else
  echo "⚠️  Some tests failed. Check the output above for details."
  echo "Tool aggregation may still have issues."
  exit 1
fi