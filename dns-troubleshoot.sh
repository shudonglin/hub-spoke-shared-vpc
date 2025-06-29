#!/bin/bash

echo "==========================="
echo "🔍 DNS Troubleshooting Script"
echo "==========================="
echo "Domain: gic-private.local"
echo "Script run time: $(date)"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "SUCCESS") echo -e "${GREEN}✅ $message${NC}" ;;
        "ERROR") echo -e "${RED}❌ $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "INFO") echo -e "${BLUE}ℹ️  $message${NC}" ;;
    esac
}

echo "==========================="
echo "📋 STEP 1: Basic Information"
echo "==========================="

# Get instance metadata
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
VPC_ID=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/)/vpc-id)
SUBNET_ID=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/)/subnet-id)

print_status "INFO" "Instance ID: $INSTANCE_ID"
print_status "INFO" "Local IP: $LOCAL_IP"
print_status "INFO" "VPC ID: $VPC_ID"
print_status "INFO" "Subnet ID: $SUBNET_ID"
print_status "INFO" "Hostname: $(hostname)"

echo ""
echo "==========================="
echo "🌐 STEP 2: Network Configuration"
echo "==========================="

# Check current DNS configuration
print_status "INFO" "Current DNS configuration:"
cat /etc/resolv.conf

echo ""
print_status "INFO" "Network interfaces:"
ip addr show | grep -E "inet |mtu"

echo ""
echo "==========================="
echo "🔍 STEP 3: DNS Resolution Tests"
echo "==========================="

# Test basic DNS resolution
print_status "INFO" "Testing basic DNS resolution..."

# Test AWS internal DNS
print_status "INFO" "Testing AWS internal DNS resolution:"
nslookup google.com 8.8.8.8 > /dev/null 2>&1 && print_status "SUCCESS" "External DNS works" || print_status "ERROR" "External DNS failed"

# Test VPC DNS resolver
VPC_DNS_SERVER=$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}')
print_status "INFO" "VPC DNS Server: $VPC_DNS_SERVER"

# Test if VPC DNS is responding
nslookup google.com $VPC_DNS_SERVER > /dev/null 2>&1 && print_status "SUCCESS" "VPC DNS resolver works" || print_status "ERROR" "VPC DNS resolver failed"

echo ""
echo "==========================="
echo "🎯 STEP 4: Custom Domain Tests"
echo "==========================="

# Test custom domain resolution
DOMAIN="gic-private.local"
HOSTNAMES=("test-spoke1" "test-spoke2" "bastion")

for hostname in "${HOSTNAMES[@]}"; do
    fqdn="${hostname}.${DOMAIN}"
    print_status "INFO" "Testing $fqdn..."
    
    # Try nslookup
    result=$(nslookup $fqdn 2>&1)
    if echo "$result" | grep -q "NXDOMAIN"; then
        print_status "ERROR" "$fqdn - NXDOMAIN (domain not found)"
    elif echo "$result" | grep -q "can't find"; then
        print_status "ERROR" "$fqdn - DNS lookup failed"
    else
        ip=$(echo "$result" | grep -A1 "Name:" | tail -1 | awk '{print $2}')
        if [[ -n "$ip" && "$ip" != "" ]]; then
            print_status "SUCCESS" "$fqdn resolves to $ip"
        else
            print_status "WARNING" "$fqdn - unclear result"
        fi
    fi
    
    # Try dig if available
    if command -v dig >/dev/null 2>&1; then
        dig_result=$(dig +short $fqdn)
        if [[ -n "$dig_result" ]]; then
            print_status "SUCCESS" "$fqdn (dig) resolves to $dig_result"
        else
            print_status "ERROR" "$fqdn (dig) - no result"
        fi
    fi
    
    echo ""
done

echo "==========================="
echo "🔧 STEP 5: DNS Cache & Fixes"
echo "==========================="

# Try to flush DNS cache
print_status "INFO" "Attempting to flush DNS cache..."
sudo systemctl restart systemd-resolved 2>/dev/null && print_status "SUCCESS" "systemd-resolved restarted" || print_status "WARNING" "Could not restart systemd-resolved"

# Wait a moment for DNS to settle
sleep 2

print_status "INFO" "Re-testing after cache flush..."
nslookup test-spoke1.gic-private.local >/dev/null 2>&1 && print_status "SUCCESS" "test-spoke1.gic-private.local now works!" || print_status "ERROR" "test-spoke1.gic-private.local still failing"

echo ""
echo "==========================="
echo "🔍 STEP 6: Advanced Diagnostics"
echo "==========================="

# Check if we can resolve EC2 internal hostnames
print_status "INFO" "Testing EC2 internal hostname resolution..."
internal_hostname="ip-$(echo $LOCAL_IP | tr '.' '-').$(curl -s http://169.254.169.254/latest/meta-data/placement/region).compute.internal"
nslookup $internal_hostname >/dev/null 2>&1 && print_status "SUCCESS" "EC2 internal hostname works: $internal_hostname" || print_status "ERROR" "EC2 internal hostname failed: $internal_hostname"

# Check if DNS over TCP works (Route53 sometimes requires this)
print_status "INFO" "Testing DNS over TCP..."
if command -v dig >/dev/null 2>&1; then
    dig +tcp test-spoke1.gic-private.local >/dev/null 2>&1 && print_status "SUCCESS" "DNS over TCP works" || print_status "ERROR" "DNS over TCP failed"
fi

echo ""
echo "==========================="
echo "🛠️  STEP 7: Manual Fixes"
echo "==========================="

print_status "INFO" "If DNS is still not working, try these manual fixes:"
echo ""
echo "1. Check Route53 private hosted zone association:"
echo "   aws route53 list-hosted-zones-by-vpc --vpc-id $VPC_ID --vpc-region $(curl -s http://169.254.169.254/latest/meta-data/placement/region)"
echo ""
echo "2. Verify DNS records exist:"
echo "   aws route53 list-resource-record-sets --hosted-zone-id <ZONE_ID>"
echo ""
echo "3. Check VPC DNS attributes:"
echo "   aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].{DnsSupport:DnsSupport,DnsHostnames:DnsHostnames}'"
echo ""
echo "4. Force DNS cache clear:"
echo "   sudo systemctl flush-dns"
echo "   sudo service network-manager restart"
echo ""
echo "5. Test with different DNS servers:"
echo "   nslookup test-spoke1.gic-private.local 8.8.8.8"
echo "   nslookup test-spoke1.gic-private.local 1.1.1.1"
echo ""

echo "==========================="
echo "📊 STEP 8: Connectivity Tests"
echo "==========================="

# If DNS works, test connectivity
if nslookup test-spoke1.gic-private.local >/dev/null 2>&1; then
    print_status "SUCCESS" "DNS is working! Testing connectivity..."
    
    # Test ping
    ping -c 3 test-spoke1.gic-private.local >/dev/null 2>&1 && print_status "SUCCESS" "Ping to test-spoke1 works" || print_status "ERROR" "Ping to test-spoke1 failed"
    
    # Test HTTP
    curl -s --connect-timeout 5 http://test-spoke1.gic-private.local >/dev/null 2>&1 && print_status "SUCCESS" "HTTP to test-spoke1 works" || print_status "WARNING" "HTTP to test-spoke1 failed (may be expected)"
    
else
    print_status "ERROR" "DNS resolution still failing - check Route53 configuration"
fi

echo ""
echo "==========================="
echo "✅ Troubleshooting Complete"
echo "==========================="
print_status "INFO" "Run this script again after making changes to re-test DNS resolution"
print_status "INFO" "For persistent issues, check AWS Route53 console for private hosted zone associations"
echo "" 