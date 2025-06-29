# 🔍 DNS Troubleshooting Guide for Route53 Private Hosted Zones

## Problem Summary

You're experiencing DNS resolution issues where:
- ✅ AWS internal hostnames work: `ip-10-1-11-173.ap-southeast-1.compute.internal`
- ❌ Custom domain names fail: `test-spoke1.gic-private.local` returns **NXDOMAIN**

## Root Cause Analysis

The issue occurs because:
1. **Route53 Private Hosted Zone** is created for `gic-private.local`
2. **DNS Records** exist for `test-spoke1.gic-private.local`, `test-spoke2.gic-private.local`
3. **Zone Association** links the hosted zone with spoke VPCs
4. **BUT**: DNS queries are not being properly resolved by the VPC DNS resolver

## 🚀 Quick Fix (Run on EC2 Instance)

### Step 1: Copy the fix scripts to your EC2 instance

```bash
# Create the scripts (copy the content from the files above)
nano fix-dns.sh
nano dns-troubleshoot.sh

# Make them executable
chmod +x fix-dns.sh dns-troubleshoot.sh
```

### Step 2: Run the quick fix

```bash
# Try the quick fix first
bash fix-dns.sh

# If that doesn't work, run detailed diagnostics
bash dns-troubleshoot.sh
```

### Step 3: Test DNS resolution

```bash
# Test DNS resolution
nslookup test-spoke1.gic-private.local
nslookup test-spoke2.gic-private.local

# Test connectivity
ping test-spoke1.gic-private.local
curl http://test-spoke1.gic-private.local
```

## 🔧 Manual Troubleshooting Steps

If the scripts don't work, try these manual steps:

### 1. Verify Route53 Configuration

```bash
# Check if Route53 zones exist (requires AWS CLI)
aws route53 list-hosted-zones --query 'HostedZones[?Name==`gic-private.local.`]'

# Check VPC associations
VPC_ID=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/)/vpc-id)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
aws route53 list-hosted-zones-by-vpc --vpc-id $VPC_ID --vpc-region $REGION
```

### 2. Check VPC DNS Settings

```bash
# Verify VPC DNS attributes
aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].{DnsSupport:DnsSupport,DnsHostnames:DnsHostnames}'
```

Should return:
```json
{
    "DnsSupport": {
        "Value": true
    },
    "DnsHostnames": {
        "Value": true
    }
}
```

### 3. Verify DNS Records Exist

```bash
# Get hosted zone ID
ZONE_ID=$(aws route53 list-hosted-zones --query 'HostedZones[?Name==`gic-private.local.`].Id' --output text | cut -d'/' -f3)

# List DNS records
aws route53 list-resource-record-sets --hosted-zone-id $ZONE_ID --query 'ResourceRecordSets[?Type==`A`]'
```

### 4. DNS Cache and Network Issues

```bash
# Flush DNS cache
sudo systemctl restart systemd-resolved
sudo systemctl flush-dns 2>/dev/null || echo "systemd flush not available"

# Check current DNS configuration
cat /etc/resolv.conf

# Test with different DNS servers
nslookup test-spoke1.gic-private.local 8.8.8.8    # Should fail (external DNS)
nslookup test-spoke1.gic-private.local             # Should work with VPC DNS
```

### 5. Test DNS Over TCP

Some Route53 issues require TCP DNS queries:

```bash
# Install dig if not available
sudo yum install bind-utils -y  # Amazon Linux
sudo apt install dnsutils -y   # Ubuntu

# Test with TCP
dig +tcp test-spoke1.gic-private.local
```

## 🛠️ Infrastructure Fixes (If DNS Configuration is Wrong)

If the problem is in the Terraform configuration:

### Option 1: Add Route53 Resolver Rules (Advanced)

The Terraform configuration includes commented resolver rules. Uncomment them if needed:

```bash
# Edit main.tf and uncomment the resolver rules section
# Then apply the changes
terraform plan
terraform apply
```

### Option 2: Recreate Route53 Resources

```bash
# Destroy and recreate Route53 resources
terraform destroy -target=aws_route53_zone.private_zone
terraform destroy -target=aws_route53_zone_association.spoke_zone_associations
terraform destroy -target=aws_route53_record.test_instance_records

terraform apply
```

### Option 3: Wait for DNS Propagation

Route53 changes can take up to 5-10 minutes to propagate:

```bash
# Wait and test periodically
for i in {1..10}; do
  echo "Test $i:"
  nslookup test-spoke1.gic-private.local && break
  sleep 30
done
```

## 🔍 Common Issues and Solutions

### Issue 1: NXDOMAIN Response
**Cause**: Route53 private hosted zone not associated with VPC
**Solution**: Check zone associations in AWS console

### Issue 2: DNS Timeout
**Cause**: Security groups blocking DNS traffic (port 53)
**Solution**: Verify security groups allow DNS (UDP/TCP 53)

### Issue 3: Wrong DNS Server
**Cause**: Instance using external DNS instead of VPC DNS
**Solution**: Check `/etc/resolv.conf` points to VPC DNS (10.x.0.2)

### Issue 4: DNS Caching
**Cause**: Old DNS entries cached
**Solution**: Restart DNS services and wait

## 📊 Verification Commands

After applying fixes, verify with:

```bash
# DNS Resolution
nslookup test-spoke1.gic-private.local
nslookup test-spoke2.gic-private.local

# Connectivity
ping -c 3 test-spoke1.gic-private.local
curl -I http://test-spoke1.gic-private.local

# Network routing
traceroute test-spoke1.gic-private.local
```

## 🆘 Emergency Workaround

If DNS still doesn't work, you can use IP addresses directly:

```bash
# Find the IP addresses
aws ec2 describe-instances --filters "Name=tag:Name,Values=*test-spoke1*" --query 'Reservations[].Instances[].PrivateIpAddress' --output text

# Use IP directly
ping 10.1.1.X  # Replace with actual IP
curl http://10.1.1.X
```

## 📞 When to Contact Support

Contact AWS Support if:
1. VPC DNS attributes are correct (both true)
2. Route53 zone associations exist
3. DNS records exist
4. All troubleshooting steps failed
5. AWS internal DNS works but Route53 doesn't

## 🎯 Expected Working State

When DNS is working correctly:

```bash
$ nslookup test-spoke1.gic-private.local
Server:         10.2.0.2
Address:        10.2.0.2#53

Name:   test-spoke1.gic-private.local
Address: 10.1.1.X

$ ping test-spoke1.gic-private.local
PING test-spoke1.gic-private.local (10.1.1.X) 56(84) bytes of data.
64 bytes from test-spoke1.gic-private.local (10.1.1.X): icmp_seq=1 ttl=254 time=1.23 ms
```

---

## 📝 Quick Reference

- **Domain**: `gic-private.local`
- **Test Hostnames**: `test-spoke1.gic-private.local`, `test-spoke2.gic-private.local`
- **Scripts**: `fix-dns.sh` (quick fix), `dns-troubleshoot.sh` (detailed diagnostics)
- **VPC DNS**: `10.x.0.2` (where x is the VPC's second octet)
- **AWS Internal DNS**: Works ✅
- **Custom DNS**: Needs fixing ❌ 