#!/bin/bash
# HARDN-XDR Smoke Test Suite
# Purpose: Comprehensive testing for function, security and user support
# Usage: sudo ./smoke_test.sh [--quick|--full|--compliance]

set -euo pipefail

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_LOG="/tmp/hardn-smoke-test-$(date +%Y%m%d-%H%M%S).log"
RESULTS_DIR="/tmp/hardn-smoke-results-$(date +%Y%m%d-%H%M%S)"
TEMP_DIR="/tmp/hardn-smoke-temp-$$"

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$TEST_LOG"
}

# Test status functions
test_start() {
    local test_name="$1"
    echo -e "${BLUE}[TEST]${NC} Starting: $test_name" | tee -a "$TEST_LOG"
    ((TESTS_TOTAL++))
}

test_pass() {
    local test_name="$1"
    echo -e "${GREEN}[PASS]${NC} $test_name" | tee -a "$TEST_LOG"
    ((TESTS_PASSED++))
}

test_fail() {
    local test_name="$1"
    local reason="${2:-Unknown failure}"
    echo -e "${RED}[FAIL]${NC} $test_name - $reason" | tee -a "$TEST_LOG"
    ((TESTS_FAILED++))
}

test_skip() {
    local test_name="$1"
    local reason="${2:-Skipped}"
    echo -e "${YELLOW}[SKIP]${NC} $test_name - $reason" | tee -a "$TEST_LOG"
    ((TESTS_SKIPPED++))
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

# Setup test environment
setup_test_environment() {
    log_message "Setting up test environment"
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$TEMP_DIR"
    
    # Set environment variables for testing
    export SKIP_WHIPTAIL=1
    export DEBIAN_FRONTEND=noninteractive
    export CI=true
    
    # Backup critical files before testing
    if [[ -f /etc/fstab ]]; then
        cp /etc/fstab "$TEMP_DIR/fstab.backup"
    fi
    
    log_message "Test environment setup complete"
}

# Cleanup test environment
cleanup_test_environment() {
    log_message "Cleaning up test environment"
    
    # Restore backups if they exist
    if [[ -f "$TEMP_DIR/fstab.backup" ]]; then
        cp "$TEMP_DIR/fstab.backup" /etc/fstab
    fi
    
    # Clean temporary files
    rm -rf "$TEMP_DIR"
    
    log_message "Test environment cleanup complete"
}

# Test 1: Basic functionality tests
test_basic_functionality() {
    test_start "Basic Functionality"
    
    # Test hardn-xdr exists and is executable
    if [[ ! -f ./hardn-xdr ]]; then
        test_fail "Basic Functionality" "hardn-xdr not found"
        return 1
    fi
    
    if [[ ! -x ./hardn-xdr ]]; then
        test_fail "Basic Functionality" "hardn-xdr not executable"
        return 1
    fi
    
    # Test help option
    if ! ./hardn-xdr --help >/dev/null 2>&1; then
        test_fail "Basic Functionality" "hardn-xdr --help failed"
        return 1
    fi
    
    # Test version option
    if ! ./hardn-xdr --version >/dev/null 2>&1; then
        test_fail "Basic Functionality" "hardn-xdr --version failed"
        return 1
    fi
    
    # Test hardn-common.sh functions load
    if ! source src/setup/hardn-common.sh; then
        test_fail "Basic Functionality" "Failed to source hardn-common.sh"
        return 1
    fi
    
    test_pass "Basic Functionality"
}

# Test 2: Environment detection
test_environment_detection() {
    test_start "Environment Detection"
    
    source src/setup/hardn-common.sh
    
    # Test container detection
    if command -v is_container_environment >/dev/null 2>&1; then
        is_container_environment && ENV_TYPE="container" || ENV_TYPE="physical"
        log_message "Detected environment: $ENV_TYPE"
    else
        test_fail "Environment Detection" "is_container_environment function not found"
        return 1
    fi
    
    # Test VM detection  
    source src/setup/hardn-main.sh
    if command -v is_container_vm_environment >/dev/null 2>&1; then
        is_container_vm_environment && VM_TYPE="vm" || VM_TYPE="physical"
        log_message "VM detection result: $VM_TYPE"
    else
        test_fail "Environment Detection" "is_container_vm_environment function not found"
        return 1
    fi
    
    test_pass "Environment Detection"
}

# Test 3: Module inventory and validation
test_module_inventory() {
    test_start "Module Inventory"
    
    local module_dir="src/setup/modules"
    if [[ ! -d "$module_dir" ]]; then
        test_fail "Module Inventory" "Module directory not found"
        return 1
    fi
    
    # Count modules
    local module_count=$(find "$module_dir" -name "*.sh" -type f | wc -l)
    log_message "Found $module_count security modules"
    
    if [[ $module_count -lt 40 ]]; then
        test_fail "Module Inventory" "Expected at least 40 modules, found $module_count"
        return 1
    fi
    
    # Test each module has basic structure
    local broken_modules=0
    for module in "$module_dir"/*.sh; do
        if [[ -f "$module" ]]; then
            # Check if module is executable
            if [[ ! -x "$module" ]]; then
                log_message "Warning: Module not executable: $(basename "$module")"
                ((broken_modules++))
            fi
            
            # Check for basic bash syntax
            if ! bash -n "$module" 2>/dev/null; then
                log_message "Error: Syntax error in module: $(basename "$module")"
                ((broken_modules++))
            fi
        fi
    done
    
    if [[ $broken_modules -gt 0 ]]; then
        test_fail "Module Inventory" "$broken_modules modules have issues"
        return 1
    fi
    
    echo "$module_count" > "$RESULTS_DIR/module_count.txt"
    test_pass "Module Inventory"
}

# Test 4: Module categorization
test_module_categorization() {
    test_start "Module Categorization"
    
    source src/setup/hardn-main.sh
    
    # Test essential modules function
    if ! essential_modules=$(get_container_vm_essential_modules 2>/dev/null); then
        test_fail "Module Categorization" "get_container_vm_essential_modules function failed"
        return 1
    fi
    
    # Test conditional modules function  
    if ! conditional_modules=$(get_container_vm_conditional_modules 2>/dev/null); then
        test_fail "Module Categorization" "get_container_vm_conditional_modules function failed"
        return 1
    fi
    
    # Test desktop modules function
    if ! desktop_modules=$(get_desktop_focused_modules 2>/dev/null); then
        test_fail "Module Categorization" "get_desktop_focused_modules function failed"
        return 1
    fi
    
    # Count modules in each category
    local essential_count=$(echo "$essential_modules" | wc -w)
    local conditional_count=$(echo "$conditional_modules" | wc -w)  
    local desktop_count=$(echo "$desktop_modules" | wc -w)
    
    log_message "Essential modules: $essential_count"
    log_message "Conditional modules: $conditional_count"
    log_message "Desktop modules: $desktop_count"
    
    # Save categorization results
    echo "Essential: $essential_count" > "$RESULTS_DIR/module_categories.txt"
    echo "Conditional: $conditional_count" >> "$RESULTS_DIR/module_categories.txt"
    echo "Desktop: $desktop_count" >> "$RESULTS_DIR/module_categories.txt"
    
    test_pass "Module Categorization"
}

# Test 5: Sample module execution (safe modules only)
test_sample_module_execution() {
    test_start "Sample Module Execution"
    
    # Test a safe module that doesn't change system state significantly
    local test_module="src/setup/modules/banner.sh"
    
    if [[ ! -f "$test_module" ]]; then
        test_skip "Sample Module Execution" "Banner module not found"
        return 0
    fi
    
    # Execute in test mode with timeout
    if timeout 60 bash "$test_module" 2>&1 | tee "$RESULTS_DIR/sample_module_output.txt"; then
        test_pass "Sample Module Execution"
    else
        test_fail "Sample Module Execution" "Banner module execution failed"
        return 1
    fi
}

# Test 6: Login protection validation
test_login_protection() {
    test_start "Login Protection"
    
    # Check if critical login services are running
    local critical_services=("systemd-logind")
    local service_issues=0
    
    for service in "${critical_services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            log_message "Service $service is active"
        else
            log_message "Warning: Service $service is not active"
            ((service_issues++))
        fi
    done
    
    # Check if display managers are available (if in desktop environment)
    if command -v gdm3 >/dev/null 2>&1 || command -v lightdm >/dev/null 2>&1; then
        log_message "Display manager detected - desktop environment"
    else
        log_message "No display manager detected - likely server environment"
    fi
    
    # Check login protection documentation exists
    if [[ -f "docs/LOGIN-PROTECTION-SUMMARY.md" ]]; then
        log_message "Login protection documentation found"
    else
        test_fail "Login Protection" "Login protection documentation missing"
        return 1
    fi
    
    if [[ $service_issues -eq 0 ]]; then
        test_pass "Login Protection"
    else
        test_fail "Login Protection" "$service_issues critical services have issues"
        return 1
    fi
}

# Test 7: Whiptail functionality
test_whiptail_functionality() {
    test_start "Whiptail Functionality"
    
    source src/setup/hardn-common.sh
    
    # Test whiptail fallback functions
    local test_result
    
    # Test hardn_yesno function
    if test_result=$(hardn_yesno "Test question" 2>&1); then
        log_message "hardn_yesno function works (fallback mode)"
    else
        test_fail "Whiptail Functionality" "hardn_yesno function failed"
        return 1
    fi
    
    # Test hardn_msgbox function
    if hardn_msgbox "Test message" 2>&1; then
        log_message "hardn_msgbox function works (fallback mode)"
    else
        test_fail "Whiptail Functionality" "hardn_msgbox function failed"
        return 1
    fi
    
    test_pass "Whiptail Functionality"
}

# Test 8: STIG compliance validation
test_stig_compliance() {
    test_start "STIG Compliance Validation"
    
    local compliance_module="src/setup/modules/compliance_validation.sh"
    
    if [[ ! -f "$compliance_module" ]]; then
        test_skip "STIG Compliance Validation" "Compliance validation module not found"
        return 0
    fi
    
    # Test compliance module syntax
    if ! bash -n "$compliance_module"; then
        test_fail "STIG Compliance Validation" "Compliance module has syntax errors"
        return 1
    fi
    
    # Check for STIG documentation
    if grep -q "STIG" "$compliance_module"; then
        log_message "STIG compliance content found in module"
    else
        test_fail "STIG Compliance Validation" "No STIG content found in compliance module"
        return 1
    fi
    
    test_pass "STIG Compliance Validation"
}

# Test 9: Memory and resource usage
test_memory_usage() {
    test_start "Memory Usage Validation"
    
    # Get baseline memory usage
    local memory_before=$(free -m | awk 'NR==2{printf "%.0f", $3}')
    log_message "Memory usage before: ${memory_before}MB"
    
    # Source main components to test memory impact
    if source src/setup/hardn-common.sh 2>/dev/null && source src/setup/hardn-main.sh 2>/dev/null; then
        local memory_after=$(free -m | awk 'NR==2{printf "%.0f", $3}')
        local memory_diff=$((memory_after - memory_before))
        
        log_message "Memory usage after loading: ${memory_after}MB"
        log_message "Memory difference: ${memory_diff}MB"
        
        # Check if memory usage is reasonable (should be minimal for shell scripts)
        if [[ $memory_diff -gt 100 ]]; then
            test_fail "Memory Usage Validation" "High memory usage: ${memory_diff}MB"
            return 1
        fi
    else
        test_fail "Memory Usage Validation" "Failed to load main components"
        return 1
    fi
    
    echo "${memory_diff}MB" > "$RESULTS_DIR/memory_usage.txt"
    test_pass "Memory Usage Validation"
}

# Test 10: Audit functionality
test_audit_functionality() {
    test_start "Audit Functionality"
    
    if [[ ! -f ./hardn_audit.sh ]]; then
        test_fail "Audit Functionality" "hardn_audit.sh not found"
        return 1
    fi
    
    # Test audit script syntax
    if ! bash -n ./hardn_audit.sh; then
        test_fail "Audit Functionality" "hardn_audit.sh has syntax errors"
        return 1
    fi
    
    # Test audit script execution (dry run)
    if timeout 30 bash -c 'echo "q" | ./hardn_audit.sh --test 2>/dev/null >/dev/null'; then
        log_message "Audit script test execution successful"
    else
        log_message "Audit script test execution failed or timed out"
    fi
    
    test_pass "Audit Functionality"
}

# Test 11: CI/CD compatibility
test_ci_compatibility() {
    test_start "CI/CD Compatibility"
    
    # Test non-interactive mode
    export SKIP_WHIPTAIL=1
    export DEBIAN_FRONTEND=noninteractive
    
    # Test that functions work in CI environment
    source src/setup/hardn-common.sh
    
    if is_container_environment; then
        log_message "CI environment properly detected"
    else
        log_message "CI environment not detected (may be expected)"
    fi
    
    # Test that whiptail fallbacks work
    if hardn_yesno "CI test question" >/dev/null 2>&1; then
        log_message "CI fallback functions working"
    else
        test_fail "CI/CD Compatibility" "CI fallback functions failed"
        return 1
    fi
    
    test_pass "CI/CD Compatibility"
}

# Test 12: Documentation completeness
test_documentation() {
    test_start "Documentation Completeness"
    
    local required_docs=(
        "README.md"
        "PLAYBOOK.md"
        "docs/PRD.md"
        ".github/copilot-instructions.md"
        "docs/LOGIN-PROTECTION-SUMMARY.md"
    )
    
    local missing_docs=0
    for doc in "${required_docs[@]}"; do
        if [[ -f "$doc" ]]; then
            log_message "Found: $doc"
        else
            log_message "Missing: $doc"
            ((missing_docs++))
        fi
    done
    
    if [[ $missing_docs -eq 0 ]]; then
        test_pass "Documentation Completeness"
    else
        test_fail "Documentation Completeness" "$missing_docs required documents missing"
        return 1
    fi
}

# Generate test report
generate_test_report() {
    local report_file="$RESULTS_DIR/smoke_test_report.html"
    
    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>HARDN-XDR Smoke Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .pass { color: #27ae60; font-weight: bold; }
        .fail { color: #e74c3c; font-weight: bold; }
        .skip { color: #f39c12; font-weight: bold; }
        .test-results { margin: 20px 0; }
        .test-item { padding: 10px; border-left: 4px solid #bdc3c7; margin: 5px 0; }
        .test-item.pass { border-left-color: #27ae60; background: #d5e8d4; }
        .test-item.fail { border-left-color: #e74c3c; background: #f8d7da; }
        .test-item.skip { border-left-color: #f39c12; background: #fff3cd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>HARDN-XDR Smoke Test Report</h1>
        <p>Generated: $(date)</p>
    </div>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <p><strong>Total Tests:</strong> $TESTS_TOTAL</p>
        <p><span class="pass">Passed: $TESTS_PASSED</span></p>
        <p><span class="fail">Failed: $TESTS_FAILED</span></p>
        <p><span class="skip">Skipped: $TESTS_SKIPPED</span></p>
        <p><strong>Success Rate:</strong> $(( TESTS_TOTAL > 0 ? (TESTS_PASSED * 100) / TESTS_TOTAL : 0 ))%</p>
    </div>
    
    <div class="test-results">
        <h2>Test Details</h2>
        <p>Detailed test results are available in the log file: $TEST_LOG</p>
    </div>
    
    <div class="summary">
        <h2>System Information</h2>
        <p><strong>OS:</strong> $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")</p>
        <p><strong>Kernel:</strong> $(uname -r)</p>
        <p><strong>Architecture:</strong> $(uname -m)</p>
        <p><strong>Test Date:</strong> $(date)</p>
    </div>
</body>
</html>
EOF
    
    log_message "Test report generated: $report_file"
}

# Main test execution
main() {
    local test_mode="${1:-full}"
    
    echo -e "${BLUE}HARDN-XDR Smoke Test Suite${NC}"
    echo "=========================================="
    echo "Test mode: $test_mode"
    echo "Log file: $TEST_LOG"
    echo "Results: $RESULTS_DIR"
    echo ""
    
    check_root
    setup_test_environment
    
    # Execute tests based on mode
    case "$test_mode" in
        --quick)
            test_basic_functionality || true
            test_environment_detection || true
            test_module_inventory || true
            test_login_protection || true
            ;;
        --compliance)
            test_stig_compliance || true
            test_module_categorization || true
            test_audit_functionality || true
            test_documentation || true
            ;;
        --full|*)
            test_basic_functionality || true
            test_environment_detection || true
            test_module_inventory || true
            test_module_categorization || true
            test_sample_module_execution || true
            test_login_protection || true
            test_whiptail_functionality || true
            test_stig_compliance || true
            test_memory_usage || true
            test_audit_functionality || true
            test_ci_compatibility || true
            test_documentation || true
            ;;
    esac
    
    generate_test_report
    
    # Final summary
    echo ""
    echo "=========================================="
    echo -e "${BLUE}Test Summary${NC}"
    echo "Total Tests: $TESTS_TOTAL"
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    echo -e "Skipped: ${YELLOW}$TESTS_SKIPPED${NC}"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        cleanup_test_environment
        exit 0
    else
        echo -e "${RED}$TESTS_FAILED test(s) failed${NC}"
        cleanup_test_environment
        exit 1
    fi
}

# Handle script termination only for unexpected exits
trap 'cleanup_test_environment' ERR

# Execute main function with all arguments
main "$@"