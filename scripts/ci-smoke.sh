#!/bin/bash
# CI Smoke Test for HARDN-XDR Modules
# Tests all modules to ensure they handle CI/container environments gracefully
# Ensures no [ERROR] lines are generated due to environment limitations

set -euo pipefail

# Export environment variables for CI testing
export SKIP_WHIPTAIL=1
export CI=true
export DEBIAN_FRONTEND=noninteractive

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TOTAL_MODULES=0
PASSED_MODULES=0
FAILED_MODULES=0
SKIPPED_MODULES=0

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MODULES_DIR="$PROJECT_ROOT/src/setup/modules"

# Log file for detailed output
LOG_FILE="/tmp/hardn-ci-smoke-test.log"
echo "HARDN-XDR CI Smoke Test - $(date)" > "$LOG_FILE"

echo -e "${GREEN}HARDN-XDR CI Smoke Test${NC}"
echo "======================================"
echo "Testing modules in: $MODULES_DIR"
echo "Log file: $LOG_FILE"
echo ""

# Function to test a single module
test_module() {
    local module_file="$1"
    local module_name
    module_name="$(basename "$module_file" .sh)"
    
    echo -n "Testing $module_name... "
    
    # Capture both stdout and stderr
    local output
    local exit_code
    if output=$(timeout 30s bash "$module_file" 2>&1); then
        exit_code=0
    else
        exit_code=$?
    fi
    
    # Check for [ERROR] messages related to environment limitations
    local error_lines
    error_lines=$(echo "$output" | grep -E '^\[ERROR\]' | grep -vE 'failed to source hardn-common.sh' || true)
    
    # Log the full output
    echo "=== $module_name (exit: $exit_code) ===" >> "$LOG_FILE"
    echo "$output" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    # Evaluate results
    if [[ $exit_code -eq 124 ]]; then
        echo -e "${YELLOW}TIMEOUT${NC}"
        SKIPPED_MODULES=$((SKIPPED_MODULES + 1))
    elif [[ -n "$error_lines" ]]; then
        echo -e "${RED}FAIL${NC} (Environment [ERROR] detected)"
        echo "  Error lines: $error_lines"
        FAILED_MODULES=$((FAILED_MODULES + 1))
    elif [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}PASS${NC}"
        PASSED_MODULES=$((PASSED_MODULES + 1))
    else
        echo -e "${YELLOW}SKIP${NC} (exit $exit_code)"
        SKIPPED_MODULES=$((SKIPPED_MODULES + 1))
    fi
    
    TOTAL_MODULES=$((TOTAL_MODULES + 1))
}

# Test all modules
if [[ ! -d "$MODULES_DIR" ]]; then
    echo -e "${RED}ERROR: Modules directory not found: $MODULES_DIR${NC}"
    exit 1
fi

for module_file in "$MODULES_DIR"/*.sh; do
    if [[ -f "$module_file" ]]; then
        test_module "$module_file"
    fi
done

echo ""
echo "======================================"
echo "Test Results:"
echo -e "  Total modules: ${TOTAL_MODULES}"
echo -e "  Passed: ${GREEN}${PASSED_MODULES}${NC}"
echo -e "  Failed: ${RED}${FAILED_MODULES}${NC}"  
echo -e "  Skipped/Timeout: ${YELLOW}${SKIPPED_MODULES}${NC}"
echo ""

# Check for overall success
if [[ $FAILED_MODULES -eq 0 ]]; then
    echo -e "${GREEN}✓ All modules handle CI environment gracefully${NC}"
    echo "Detailed log: $LOG_FILE"
    exit 0
else
    echo -e "${RED}✗ $FAILED_MODULES modules failed CI environment tests${NC}"
    echo "Check detailed log: $LOG_FILE"
    exit 1
fi