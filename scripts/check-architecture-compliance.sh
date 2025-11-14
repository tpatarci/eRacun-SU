#!/bin/bash
#
# Architecture Compliance Checker
#
# Enforces strict bounded context isolation per ADR-005
# Run as pre-commit hook or in CI/CD pipeline
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

VIOLATIONS=0

echo "🔍 Checking monorepo architecture compliance..."
echo ""

# ==============================================================================
# Rule 1: No Cross-Service Imports
# ==============================================================================
echo "📦 Rule 1: Checking for cross-service imports..."

if grep -r "from.*'\.\./\.\./.*services/" services/*/src --include="*.ts" 2>/dev/null; then
  echo -e "${RED}❌ VIOLATION: Cross-service imports detected!${NC}"
  echo ""
  echo "Services MUST NOT import code from other services."
  echo "Use message bus communication or shared proto-generated types."
  echo ""
  echo "See: docs/adr/005-bounded-context-isolation.md"
  VIOLATIONS=$((VIOLATIONS + 1))
else
  echo -e "${GREEN}✅ No cross-service imports found${NC}"
fi

echo ""

# ==============================================================================
# Rule 2: No Direct HTTP Calls to Internal Services
# ==============================================================================
echo "🌐 Rule 2: Checking for direct service-to-service HTTP calls..."

# Check for hardcoded internal service URLs in axios/fetch calls
# Pattern matches: http[s]://hostname:port where hostname has no dots (internal services)
# Does NOT match: https://external.domain.com:port (has dots = external)
# Excludes: Infrastructure (rabbitmq, postgres, redis), localhost, comments
if grep -rE "http[s]?://[^/.:]+:[0-9]" services/*/src --include="*.ts" 2>/dev/null | \
   grep -v "// TODO" | \
   grep -vE "^[[:space:]]*//" | \
   grep -v "localhost" | \
   grep -v "127.0.0.1" | \
   grep -v "rabbitmq" | \
   grep -v "postgres" | \
   grep -v "redis" | \
   grep -vE "https?://[^/]*\.[^/]+" | \
   grep -v "e.g.," | \
   grep -v "example:"; then
  echo -e "${RED}❌ VIOLATION: Direct service-to-service HTTP calls detected!${NC}"
  echo ""
  echo "Services MUST communicate via:"
  echo "  - Message bus (RabbitMQ) for commands/events"
  echo "  - API Gateway for external→internal queries"
  echo ""
  echo "Forbidden patterns:"
  echo "  - axios.get('http://health-monitor:8084/...')"
  echo "  - axios.post('http://notification-service:8080/...')"
  echo ""
  echo "Required pattern:"
  echo "  messageBus.request({ exchange: 'health.queries', ... })"
  echo ""
  echo "See: docs/adr/005-bounded-context-isolation.md"
  VIOLATIONS=$((VIOLATIONS + 1))
else
  echo -e "${GREEN}✅ No direct service HTTP calls found${NC}"
fi

echo ""

# ==============================================================================
# Rule 3: No Cross-Service NPM Dependencies
# ==============================================================================
echo "📚 Rule 3: Checking for cross-service npm dependencies..."

# Check if any service depends on another service package
if grep -r '"@eracun/' services/*/package.json | grep -v "\"name\":" | grep -v node_modules; then
  echo -e "${RED}❌ VIOLATION: Cross-service npm dependencies detected!${NC}"
  echo ""
  echo "Services MUST NOT depend on other services' npm packages."
  echo "This creates tight coupling and prevents independent deployment."
  echo ""
  echo "See: docs/adr/005-bounded-context-isolation.md"
  VIOLATIONS=$((VIOLATIONS + 1))
else
  echo -e "${GREEN}✅ No cross-service dependencies found${NC}"
fi

echo ""

# ==============================================================================
# Rule 4: Proto Files Must Be Versioned
# ==============================================================================
echo "📄 Rule 4: Checking proto contract versioning..."

if [ -d "docs/api-contracts/protobuf" ]; then
  UNVERSIONED=$(grep -L "package eracun\.v[0-9]" docs/api-contracts/protobuf/*.proto 2>/dev/null || true)

  if [ -n "$UNVERSIONED" ]; then
    echo -e "${RED}❌ VIOLATION: Unversioned proto files detected!${NC}"
    echo ""
    echo "All proto files MUST use versioned packages:"
    echo "  package eracun.v1.service_name;"
    echo ""
    echo "Unversioned files:"
    echo "$UNVERSIONED"
    echo ""
    echo "See: docs/adr/005-bounded-context-isolation.md"
    VIOLATIONS=$((VIOLATIONS + 1))
  else
    echo -e "${GREEN}✅ All proto files are versioned${NC}"
  fi
else
  echo -e "${YELLOW}⚠️  No proto contracts found (skipping check)${NC}"
fi

echo ""

# ==============================================================================
# Rule 5: Shared Code Limited to Test Config
# ==============================================================================
echo "📂 Rule 5: Checking shared/ directory for runtime code..."

if [ -d "shared" ]; then
  # Allow only test-related shared code (jest-config, test-utils, etc.)
  RUNTIME_SHARED=$(find shared -type f \( -name "*.ts" -o -name "*.js" \) \
    ! -path "*/jest-config/*" \
    ! -path "*/test-utils/*" \
    ! -name "*.test.ts" \
    ! -name "*.spec.ts" \
    2>/dev/null || true)

  if [ -n "$RUNTIME_SHARED" ]; then
    echo -e "${RED}❌ VIOLATION: Runtime code in shared/ directory detected!${NC}"
    echo ""
    echo "The shared/ directory MUST contain ONLY:"
    echo "  - Test configuration (jest-config/)"
    echo "  - Test utilities (test-utils/)"
    echo ""
    echo "Runtime code found:"
    echo "$RUNTIME_SHARED"
    echo ""
    echo "Move business logic to individual services or define contracts in proto files."
    echo ""
    echo "See: CLAUDE.md §2.3 (Shared Libraries - Performance Considerations)"
    VIOLATIONS=$((VIOLATIONS + 1))
  else
    echo -e "${GREEN}✅ Shared directory contains only test config${NC}"
  fi
else
  echo -e "${GREEN}✅ No shared directory exists${NC}"
fi

echo ""

# ==============================================================================
# Summary
# ==============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $VIOLATIONS -eq 0 ]; then
  echo -e "${GREEN}✅ Architecture compliance check PASSED${NC}"
  echo ""
  echo "All services follow hub-and-spokes architecture."
  echo "Bounded contexts are properly isolated."
  exit 0
else
  echo -e "${RED}❌ Architecture compliance check FAILED${NC}"
  echo ""
  echo "Found $VIOLATIONS violation(s)"
  echo ""
  echo "Next steps:"
  echo "  1. Review violations above"
  echo "  2. Consult docs/adr/005-bounded-context-isolation.md"
  echo "  3. Fix violations and re-run this script"
  echo ""
  echo "To bypass this check (NOT RECOMMENDED):"
  echo "  git commit --no-verify"
  exit 1
fi
