#!/bin/bash

echo "🔧 DNS Quick Fix Script for Route53 Private Hosted Zone"
echo "======================================================"
echo "Domain: gic-private.local"
echo "Time: $(date)"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to print status
log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR: $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING: $1${NC}"
}

log "Starting DNS troubleshooting and fixes..."

# 1. Flush DNS caches
log "Step 1: Flushing DNS caches..."
sudo systemctl restart systemd-resolved 2>/dev/null || warn "Could not restart systemd-resolved"
sudo systemctl restart dnsmasq 2>/dev/null || log "dnsmasq not running (OK)"

# 2. Check and fix /etc/resolv.conf if needed
log "Step 2: Checking DNS configuration..."
if ! grep -q "10\." /etc/resolv.conf; then
    error "VPC DNS server not found in /etc/resolv.conf"
    log "Current resolv.conf:"
    cat /etc/resolv.conf
else
    log "VPC DNS server found in resolv.conf"
fi

# 3. Wait for DNS propagation
log "Step 3: Waiting for DNS propagation (10 seconds)..."
sleep 10

# 4. Test DNS resolution
log "Step 4: Testing DNS resolution..."
DOMAIN="gic-private.local"
HOSTNAMES=("test-spoke1" "test-spoke2")

for hostname in "${HOSTNAMES[@]}"; do
    fqdn="${hostname}.${DOMAIN}"
    log "Testing $fqdn..."
    
    if nslookup $fqdn >/dev/null 2>&1; then
        ip=$(nslookup $fqdn | grep -A1 "Name:" | tail -1 | awk '{print $2}' | head -1)
        log "✅ $fqdn resolves to $ip"
        
        # Test connectivity
        if ping -c 1 -W 2 $fqdn >/dev/null 2>&1; then
            log "✅ Ping to $fqdn successful"
        else
            warn "Ping to $fqdn failed (may be security group rules)"
        fi
    else
        error "❌ $fqdn DNS resolution failed"
    fi
done

# 5. Alternative DNS test with dig
if command -v dig >/dev/null 2>&1; then
    log "Step 5: Testing with dig..."
    dig +short test-spoke1.gic-private.local | head -1 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && log "✅ dig resolution works" || error "❌ dig resolution failed"
fi

# 6. Check Route53 association (if AWS CLI available)
if command -v aws >/dev/null 2>&1; then
    log "Step 6: Checking Route53 hosted zone associations..."
    VPC_ID=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/)/vpc-id)
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
    
    if aws route53 list-hosted-zones-by-vpc --vpc-id $VPC_ID --vpc-region $REGION >/dev/null 2>&1; then
        log "Route53 VPC associations found"
    else
        error "Route53 VPC associations check failed"
    fi
else
    warn "AWS CLI not available - skipping Route53 checks"
fi

echo ""
echo "======================================================"
echo "🔍 DNS Fix Summary"
echo "======================================================"

# Final test
if nslookup test-spoke1.gic-private.local >/dev/null 2>&1; then
    log "✅ SUCCESS: DNS is now working!"
    log "You can now use hostnames like:"
    log "  - test-spoke1.gic-private.local"
    log "  - test-spoke2.gic-private.local"
    echo ""
    log "Try running your connectivity tests again:"
    log "  ping test-spoke1.gic-private.local"
    log "  curl http://test-spoke1.gic-private.local"
else
    error "❌ DNS still not working after fixes"
    error "This likely indicates a Route53 configuration issue"
    echo ""
    error "Manual steps required:"
    echo "1. Check AWS Route53 console"
    echo "2. Verify private hosted zone exists for 'gic-private.local'"
    echo "3. Verify zone is associated with your VPC"
    echo "4. Verify DNS records exist for test-spoke1, test-spoke2"
    echo "5. Verify VPC has DNS resolution and DNS hostnames enabled"
    echo ""
    error "Run 'bash dns-troubleshoot.sh' for detailed diagnostics"
fi

echo ""
log "DNS fix script completed at $(date)" 