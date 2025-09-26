#!/bin/bash

echo "========================================"
echo "    FINAL TOOL CALL TEST REPORT"
echo "========================================"
echo "Testing against: kgateway.nydig-dev.cloud/bedrock"
echo "Endpoint: /v1/messages"
echo "Date: $(date)"
echo "========================================"

total_tests=0
passed_tests=0

# Test 1: Basic Tool Call
echo -e "\n🧪 Test 1: Basic Tool Call"
echo "----------------------------------------"
if ./test-tool-calls-basic.sh >/dev/null 2>&1; then
    echo "✅ PASSED - Single tool call with result processed correctly"
    ((passed_tests++))
else
    echo "❌ FAILED - Basic tool call failed"
fi
((total_tests++))

# Test 2: Multiple Tool Calls
echo -e "\n🧪 Test 2: Multiple Tool Calls"
echo "----------------------------------------"
if ./test-tool-calls-multiple.sh >/dev/null 2>&1; then
    echo "✅ PASSED - Multiple tool calls (3) processed correctly"
    ((passed_tests++))
else
    echo "❌ FAILED - Multiple tool calls failed"
fi
((total_tests++))

# Test 3: Edge Cases
echo -e "\n🧪 Test 3: Edge Cases"
echo "----------------------------------------"
if ./test-tool-calls-edge-cases.sh >/dev/null 2>&1; then
    echo "✅ PASSED - Missing results, empty results, mixed content handled"
    ((passed_tests++))
else
    echo "❌ FAILED - Edge cases failed"
fi
((total_tests++))

# Test 4: Concurrent Requests
echo -e "\n🧪 Test 4: Concurrent Requests (Race Conditions)"
echo "----------------------------------------"
if ./test-tool-calls-concurrent.sh >/dev/null 2>&1; then
    echo "✅ PASSED - 10 concurrent requests, no race conditions detected"
    ((passed_tests++))
else
    echo "❌ FAILED - Concurrent requests failed"
fi
((total_tests++))

echo -e "\n========================================"
echo "           FINAL RESULTS"
echo "========================================"
echo "Total Tests: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $((total_tests - passed_tests))"
echo "Success Rate: $(( (passed_tests * 100) / total_tests ))%"
echo "========================================"

if [ $passed_tests -eq $total_tests ]; then
    echo -e "\n🎉 ALL TESTS PASSED!"
    echo "✅ Tool aggregation fix is working correctly"
    echo "✅ Messages API → Universal → Bedrock pipeline fixed"
    echo "✅ No race conditions detected"
    echo "✅ Edge cases handled gracefully"
    echo ""
    echo "🔧 Issues Fixed:"
    echo "  • Tool result duplication eliminated"
    echo "  • Assistant→User→Tool sequence handled properly"
    echo "  • Universal format Tool messages aggregated correctly"
    echo "  • Bedrock ToolResult blocks created without errors"
    exit 0
else
    echo -e "\n⚠️ Some tests failed"
    echo "Tool aggregation may still have issues"
    exit 1
fi