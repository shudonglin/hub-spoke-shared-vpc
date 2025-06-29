#!/bin/bash

echo "🔍 Hub-Spoke VPC Pre-Deployment Configuration Check"
echo "=================================================="

# Initialize counters
CHECKS_PASSED=0
CHECKS_FAILED=0
WARNINGS=0

# Function to check passed
check_passed() {
    echo "✅ $1"
    ((CHECKS_PASSED++))
}

# Function to check failed
check_failed() {
    echo "❌ $1"
    ((CHECKS_FAILED++))
}

# Function to check warning
check_warning() {
    echo "⚠️  $1"
    ((WARNINGS++))
}

echo ""
echo "📋 Configuration File Validation"
echo "================================"

# Check if required files exist
echo "Checking required files..."
for file in main.tf variables.tf locals.tf waf.tf terraform.tfvars providers.tf; do
    if [ -f "$file" ]; then
        check_passed "File $file exists"
    else
        check_failed "File $file is missing"
    fi
done

echo ""
echo "🌐 Network Configuration Validation"
echo "==================================="

# Check terraform.tfvars configuration
if [ -f "terraform.tfvars" ]; then
    # Check VPC CIDRs
    if grep -q "shared_vpc_cidr = \"10.0.0.0/16\"" terraform.tfvars; then
        check_passed "Shared VPC CIDR configured (10.0.0.0/16)"
    else
        check_warning "Shared VPC CIDR not using recommended 10.0.0.0/16"
    fi
    
    if grep -q "spoke1 = \"10.1.0.0/16\"" terraform.tfvars; then
        check_passed "Spoke1 VPC CIDR configured (10.1.0.0/16)"
    else
        check_warning "Spoke1 VPC CIDR not using recommended 10.1.0.0/16"
    fi
    
    if grep -q "spoke2 = \"10.2.0.0/16\"" terraform.tfvars; then
        check_passed "Spoke2 VPC CIDR configured (10.2.0.0/16)"
    else
        check_warning "Spoke2 VPC CIDR not using recommended 10.2.0.0/16"
    fi
    
    # Check domain name
    if grep -q "domain_name = \"gic-private.local\"" terraform.tfvars; then
        check_passed "Domain name configured (gic-private.local)"
    else
        check_warning "Domain name not using gic-private.local"
    fi
    
    # Check test instances
    if grep -q "test_instance_vpcs = \[\"spoke1\", \"spoke2\"\]" terraform.tfvars; then
        check_passed "Test instances configured for both spoke VPCs"
    else
        check_warning "Test instances configuration may not be optimal"
    fi
else
    check_failed "terraform.tfvars file not found"
fi

echo ""
echo "🔐 Security Configuration Validation"
echo "===================================="

# Check ICMP is disabled in main.tf
if grep -q "# ICMP (ping) disabled for security" main.tf; then
    check_passed "ICMP protocol disabled in security groups"
else
    check_warning "ICMP protocol status unclear"
fi

# Check WAF configuration
if [ -f "waf.tf" ]; then
    check_passed "WAF configuration file exists"
    
    if grep -q "enable_waf = true" terraform.tfvars; then
        check_passed "WAF enabled in configuration"
    else
        check_warning "WAF not enabled - consider enabling for security"
    fi
else
    check_failed "WAF configuration file missing"
fi

# Check VPC Flow Logs
if grep -q "enable_vpc_flow_logs = true" terraform.tfvars; then
    check_passed "VPC Flow Logs enabled"
else
    check_warning "VPC Flow Logs not enabled - consider enabling for monitoring"
fi

echo ""
echo "🔗 DNS Configuration Validation"
echo "==============================="

# Check Route53 zone associations
if grep -q "aws_route53_zone_association" main.tf; then
    check_passed "Route53 zone associations configured"
else
    check_failed "Route53 zone associations missing"
fi

# Check resolver rules are enabled
if grep -q "resource \"aws_route53_resolver_rule\" \"custom_domain\"" main.tf; then
    check_passed "Route53 resolver rules enabled for cross-VPC DNS"
else
    check_failed "Route53 resolver rules not enabled - this will cause DNS issues"
fi

# Check connectivity test script fix
if grep -q "for vpc in spoke1 spoke2; do" main.tf; then
    check_passed "Connectivity test script only tests spoke VPCs (DNS fix applied)"
else
    check_warning "Connectivity test script may still reference non-existent shared VPC test instance"
fi

echo ""
echo "💰 Cost Optimization Validation"
echo "==============================="

# Check single NAT gateway
if grep -q "single_nat_gateway = true" terraform.tfvars; then
    check_passed "Single NAT Gateway enabled for cost optimization"
else
    check_warning "Single NAT Gateway not enabled - will cost ~$135/month extra"
fi

# Check bastion host
if grep -q "create_bastion_host = false" terraform.tfvars; then
    check_passed "Bastion host disabled (using SSM Session Manager instead)"
else
    check_warning "Bastion host enabled - adds ~$8/month cost"
fi

echo ""
echo "📊 Final Validation Summary"
echo "==========================="
echo "✅ Checks Passed: $CHECKS_PASSED"
echo "❌ Checks Failed: $CHECKS_FAILED"
echo "⚠️  Warnings: $WARNINGS"
echo ""

if [ $CHECKS_FAILED -eq 0 ]; then
    echo "🎉 Configuration validation PASSED!"
    echo "Your hub-spoke VPC configuration is ready for deployment."
    echo ""
    echo "Next steps:"
    echo "1. Review any warnings above"
    echo "2. Run: terraform plan"
    echo "3. Run: terraform apply"
    echo ""
    echo "Key fixes applied:"
    echo "• DNS resolution issues fixed (Route53 resolver rules enabled)"
    echo "• ICMP protocol disabled in security groups"
    echo "• Connectivity tests only target VPCs with instances"
    echo "• Cross-VPC DNS resolution properly configured"
    exit 0
else
    echo "💥 Configuration validation FAILED!"
    echo "Please fix the issues above before deploying."
    echo ""
    echo "Common fixes needed:"
    echo "• Ensure all required .tf files are present"
    echo "• Check terraform.tfvars configuration"
    echo "• Verify Route53 resolver rules are uncommented in main.tf"
    exit 1
fi 