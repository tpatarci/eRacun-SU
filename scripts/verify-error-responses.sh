#!/bin/bash

# Verification script for error response format
# This script tests all API endpoints that can return errors
# and verifies they include code, message, and requestId fields

set -e

BASE_URL="http://localhost:3000"
FAILED=0
PASSED=0

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "Error Response Format Verification"
echo "========================================="
echo ""

# Function to test an endpoint
test_endpoint() {
  local test_name="$1"
  local method="$2"
  local url="$3"
  local data="$4"
  local expected_status="$5"
  shift 5
  local expected_fields=("$@")

  echo -n "Testing: $test_name ... "

  # Make the request
  if [ -z "$data" ]; then
    response=$(curl -s -w "\n%{http_code}" -X "$method" "$BASE_URL$url" -H "Content-Type: application/json")
  else
    response=$(curl -s -w "\n%{http_code}" -X "$method" "$BASE_URL$url" -H "Content-Type: application/json" -d "$data")
  fi

  # Split response and status code
  status_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | sed '$d')

  # Check status code
  if [ "$status_code" != "$expected_status" ]; then
    echo -e "${RED}FAILED${NC}"
    echo "  Expected status $expected_status, got $status_code"
    echo "  Response: $body"
    FAILED=$((FAILED + 1))
    return
  fi

  # Check each expected field
  all_fields_present=true
  for field in "${expected_fields[@]}"; do
    if ! echo "$body" | grep -q "\"$field\""; then
      all_fields_present=false
      break
    fi
  done

  if [ "$all_fields_present" = true ]; then
    echo -e "${GREEN}PASSED${NC}"
    echo "  Status: $status_code"
    echo "  Fields: ${expected_fields[*]}"
    echo "  Response: $body"
    PASSED=$((PASSED + 1))
  else
    echo -e "${RED}FAILED${NC}"
    echo "  Missing required fields"
    echo "  Expected: ${expected_fields[*]}"
    echo "  Response: $body"
    FAILED=$((FAILED + 1))
  fi

  echo ""
}

# Check if server is running
echo -n "Checking if server is running ... "
if ! curl -s "$BASE_URL/health" > /dev/null 2>&1; then
  echo -e "${RED}FAILED${NC}"
  echo "Server is not running at $BASE_URL"
  echo "Please start the server first with: npm run dev"
  exit 1
fi
echo -e "${GREEN}OK${NC}"
echo ""

# Test all error scenarios
echo "Testing error responses..."
echo ""

# 1. Not Found Error - GET /api/v1/invoices/:id (non-existent ID)
test_endpoint \
  "NotFoundError - GET /api/v1/invoices/nonexistent-id" \
  "GET" \
  "/api/v1/invoices/nonexistent-id" \
  "" \
  "404" \
  "code" "message" "requestId"

# 2. Not Found Error - GET /api/v1/invoices/:id/status (non-existent ID)
test_endpoint \
  "NotFoundError - GET /api/v1/invoices/nonexistent-id/status" \
  "GET" \
  "/api/v1/invoices/nonexistent-id/status" \
  "" \
  "404" \
  "code" "message" "requestId"

# 3. Bad Request Error - GET /api/v1/invoices (missing oib parameter)
test_endpoint \
  "BadRequestError - GET /api/v1/invoices (missing oib)" \
  "GET" \
  "/api/v1/invoices" \
  "" \
  "400" \
  "code" "message" "requestId"

# 4. Validation Error - POST /api/v1/invoices (empty body)
test_endpoint \
  "ValidationError - POST /api/v1/invoices (empty body)" \
  "POST" \
  "/api/v1/invoices" \
  "{}" \
  "400" \
  "code" "message" "requestId" "errors"

# 5. Validation Error - POST /api/v1/invoices (invalid data)
test_endpoint \
  "ValidationError - POST /api/v1/invoices (invalid data)" \
  "POST" \
  "/api/v1/invoices" \
  '{"oib": "invalid", "invoiceNumber": 123}' \
  "400" \
  "code" "message" "requestId" "errors"

# 6. Internal Error - GET /health/db (when DB is unavailable)
# Note: This test requires the database to be unavailable, so we'll skip it
# or the test might fail if the DB is available

# 7. Not Found Error - GET /nonexistent-route (undefined route)
test_endpoint \
  "NotFoundError - GET /nonexistent-route" \
  "GET" \
  "/nonexistent-route" \
  "" \
  "404" \
  "code" "message" "requestId"

# Summary
echo "========================================="
echo "Summary"
echo "========================================="
echo -e "Total tests: $((PASSED + FAILED))"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
  echo -e "${GREEN}All error response format tests passed!${NC}"
  exit 0
else
  echo -e "${RED}Some tests failed. Please review the output above.${NC}"
  exit 1
fi
