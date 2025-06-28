#!/bin/bash

# WAF Testing Script for Hub-Spoke Architecture
# This script helps test various WAF rules and functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ALB_DNS_NAME=""
PROJECT_NAME="hub-spoke-shared-vpc"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to get ALB DNS name from Terraform output
get_alb_dns() {
    print_status "Getting ALB DNS name from Terraform output..."
    
    if command -v terraform &> /dev/null; then
        ALB_DNS_NAME=$(terraform output -raw alb_dns_name 2>/dev/null || echo "")
        
        if [ -z "$ALB_DNS_NAME" ] || [ "$ALB_DNS_NAME" = "null" ]; then
            print_error "Could not get ALB DNS name from Terraform output"
            print_warning "Make sure WAF is enabled and Terraform has been applied"
            echo "You can manually set ALB_DNS_NAME variable in this script"
            exit 1
        else
            print_success "ALB DNS Name: $ALB_DNS_NAME"
        fi
    else
        print_error "Terraform not found. Please install Terraform or manually set ALB_DNS_NAME"
        exit 1
    fi
}

# Function to test basic connectivity
test_basic_connectivity() {
    print_status "Testing basic connectivity..."
    
    local endpoints=("shared" "spoke1" "spoke2")
    
    for endpoint in "${endpoints[@]}"; do
        print_status "Testing http://$ALB_DNS_NAME/$endpoint"
        
        response=$(curl -s -o /dev/null -w "%{http_code}" "http://$ALB_DNS_NAME/$endpoint" || echo "000")
        
        if [ "$response" = "200" ]; then
            print_success "$endpoint endpoint is accessible (HTTP $response)"
        else
            print_warning "$endpoint endpoint returned HTTP $response"
        fi
    done
}

# Function to test rate limiting
test_rate_limiting() {
    print_status "Testing rate limiting (sending 50 rapid requests)..."
    
    local blocked_count=0
    local allowed_count=0
    
    for i in {1..50}; do
        response=$(curl -s -o /dev/null -w "%{http_code}" "http://$ALB_DNS_NAME/shared" || echo "000")
        
        if [ "$response" = "403" ]; then
            ((blocked_count++))
        elif [ "$response" = "200" ]; then
            ((allowed_count++))
        fi
        
        # Small delay to not overwhelm the system
        sleep 0.1
    done
    
    print_status "Rate limiting test results:"
    echo "  - Allowed requests: $allowed_count"
    echo "  - Blocked requests: $blocked_count"
    
    if [ $blocked_count -gt 0 ]; then
        print_success "Rate limiting is working (some requests were blocked)"
    else
        print_warning "Rate limiting may not be configured or threshold not reached"
    fi
}

# Function to test SQL injection protection
test_sql_injection() {
    print_status "Testing SQL injection protection..."
    
    local payloads=(
        "' OR '1'='1"
        "'; DROP TABLE users; --"
        "1' UNION SELECT * FROM users --"
        "admin'--"
    )
    
    local blocked=0
    
    for payload in "${payloads[@]}"; do
        print_status "Testing payload: $payload"
        
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "user_input=$payload" \
            "http://$ALB_DNS_NAME/shared" || echo "000")
        
        if [ "$response" = "403" ]; then
            print_success "SQL injection blocked (HTTP $response)"
            ((blocked++))
        else
            print_warning "SQL injection not blocked (HTTP $response)"
        fi
    done
    
    if [ $blocked -gt 0 ]; then
        print_success "SQL injection protection is working ($blocked/$# payloads blocked)"
    else
        print_warning "SQL injection protection may not be working properly"
    fi
}

# Function to test XSS protection
test_xss_protection() {
    print_status "Testing XSS protection..."
    
    local payloads=(
        "<script>alert('xss')</script>"
        "<img src=x onerror=alert('xss')>"
        "javascript:alert('xss')"
        "<svg onload=alert('xss')>"
    )
    
    local blocked=0
    
    for payload in "${payloads[@]}"; do
        print_status "Testing XSS payload: $payload"
        
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "comment=$payload" \
            "http://$ALB_DNS_NAME/shared" || echo "000")
        
        if [ "$response" = "403" ]; then
            print_success "XSS blocked (HTTP $response)"
            ((blocked++))
        else
            print_warning "XSS not blocked (HTTP $response)"
        fi
    done
    
    if [ $blocked -gt 0 ]; then
        print_success "XSS protection is working ($blocked/$# payloads blocked)"
    else
        print_warning "XSS protection may not be working properly"
    fi
}

# Function to test large request blocking
test_large_request() {
    print_status "Testing large request handling..."
    
    # Create a large payload (10KB)
    large_payload=$(python3 -c "print('A' * 10240)" 2>/dev/null || echo $(head -c 10240 /dev/zero | tr '\0' 'A'))
    
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "data=$large_payload" \
        "http://$ALB_DNS_NAME/shared" || echo "000")
    
    if [ "$response" = "403" ]; then
        print_success "Large request blocked (HTTP $response)"
    elif [ "$response" = "413" ]; then
        print_success "Large request blocked by server (HTTP $response)"
    else
        print_warning "Large request not blocked (HTTP $response)"
    fi
}

# Function to check WAF logs
check_waf_logs() {
    print_status "Checking WAF CloudWatch logs (last 10 minutes)..."
    
    if command -v aws &> /dev/null; then
        local log_group="/aws/waf/$PROJECT_NAME"
        local end_time=$(date +%s)000
        local start_time=$((end_time - 600000))  # 10 minutes ago
        
        print_status "Querying log group: $log_group"
        
        # Check if log group exists
        if aws logs describe-log-groups --log-group-name-prefix "$log_group" --query 'logGroups[0].logGroupName' --output text 2>/dev/null | grep -q "$log_group"; then
            
            # Get recent blocked requests
            local blocked_requests=$(aws logs filter-log-events \
                --log-group-name "$log_group" \
                --start-time "$start_time" \
                --end-time "$end_time" \
                --filter-pattern '{ $.action = "BLOCK" }' \
                --query 'length(events)' \
                --output text 2>/dev/null || echo "0")
            
            print_status "Recent blocked requests (last 10 minutes): $blocked_requests"
            
            if [ "$blocked_requests" -gt 0 ]; then
                print_success "WAF is actively blocking requests"
            else
                print_warning "No blocked requests found in recent logs"
            fi
        else
            print_warning "WAF log group not found: $log_group"
            print_warning "Logs may take a few minutes to appear after first requests"
        fi
    else
        print_warning "AWS CLI not found. Cannot check CloudWatch logs"
    fi
}

# Function to show WAF metrics
show_waf_metrics() {
    print_status "WAF CloudWatch Metrics Dashboard:"
    echo ""
    echo "View your WAF metrics in the AWS Console:"
    echo "https://console.aws.amazon.com/cloudwatch/home?region=$(aws configure get region 2>/dev/null || echo 'us-east-1')#metricsV2:graph=~();search=$PROJECT_NAME"
    echo ""
    echo "Key metrics to monitor:"
    echo "  - AllowedRequests: Total allowed requests"
    echo "  - BlockedRequests: Total blocked requests" 
    echo "  - RateLimitRule: Rate limiting violations"
    echo "  - CommonRuleSetMetric: OWASP Top 10 blocks"
    echo "  - SQLiRuleSetMetric: SQL injection blocks"
}

# Main menu
show_menu() {
    echo ""
    echo "========================================"
    echo "   WAF Testing Script"
    echo "========================================"
    echo "1. Test basic connectivity"
    echo "2. Test rate limiting"
    echo "3. Test SQL injection protection"
    echo "4. Test XSS protection"
    echo "5. Test large request handling"
    echo "6. Check WAF logs"
    echo "7. Show metrics dashboard"
    echo "8. Run all tests"
    echo "9. Exit"
    echo "========================================"
}

# Function to run all tests
run_all_tests() {
    print_status "Running all WAF tests..."
    echo ""
    
    test_basic_connectivity
    echo ""
    
    test_rate_limiting
    echo ""
    
    test_sql_injection
    echo ""
    
    test_xss_protection
    echo ""
    
    test_large_request
    echo ""
    
    check_waf_logs
    echo ""
    
    show_waf_metrics
}

# Main execution
main() {
    echo "WAF Testing Script for Hub-Spoke Architecture"
    echo "============================================="
    
    # Get ALB DNS name
    get_alb_dns
    
    while true; do
        show_menu
        read -p "Enter your choice (1-9): " choice
        
        case $choice in
            1) test_basic_connectivity ;;
            2) test_rate_limiting ;;
            3) test_sql_injection ;;
            4) test_xss_protection ;;
            5) test_large_request ;;
            6) check_waf_logs ;;
            7) show_waf_metrics ;;
            8) run_all_tests ;;
            9) 
                print_status "Exiting WAF testing script"
                exit 0
                ;;
            *)
                print_error "Invalid choice. Please enter 1-9"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Check dependencies
if ! command -v curl &> /dev/null; then
    print_error "curl is required but not installed"
    exit 1
fi

# Run main function
main "$@" 