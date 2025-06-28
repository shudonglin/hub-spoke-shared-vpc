# AWS WAF Configuration Guide

This document explains the AWS WAF (Web Application Firewall) implementation in your hub-spoke architecture.

## Architecture Overview

The WAF implementation adds:
- **Application Load Balancer (ALB)** in the shared VPC public subnets
- **AWS WAF Web ACL** with comprehensive rule sets
- **Target Groups** for your test instances
- **CloudWatch Logging** for monitoring and analysis

```
Internet → AWS WAF → Application Load Balancer → Target Groups → Test Instances
```

## Components Created

### 1. Application Load Balancer
- **Location**: Shared VPC public subnets
- **Type**: Application Load Balancer (Layer 7)
- **Routing**: Path-based routing to different VPCs
- **Health Checks**: HTTP health checks on port 80

### 2. WAF Web ACL Rules

#### Priority Order (Lower = Higher Priority)
1. **Allow Specific IPs** (Priority 1)
2. **Block Specific IPs** (Priority 2)  
3. **Geographic Blocking** (Priority 3)
4. **Rate Limiting** (Priority 10)
5. **AWS Managed Rules** (Priority 20-24)
6. **Custom Rules** (Priority 30-31)

#### Rule Details

##### IP-Based Rules
- **Allow List**: Always allow specific IP addresses (bypasses all other rules)
- **Block List**: Always block specific IP addresses
- **Rate Limiting**: Block IPs exceeding request threshold (default: 2000 req/5min)

##### Geographic Rules
- **Country Blocking**: Block requests from specific countries
- Uses ISO 3166-1 alpha-2 country codes (e.g., "CN", "RU", "KP")

##### AWS Managed Rule Groups
- **Core Rule Set**: OWASP Top 10 protection
- **Admin Protection**: Protects admin interfaces
- **Known Bad Inputs**: Blocks known malicious patterns
- **SQL Injection**: Prevents SQL injection attacks
- **Linux OS**: Linux-specific protection rules

##### Custom Rules
- **SQL Injection**: Custom patterns for SQL injection
- **XSS Protection**: Cross-site scripting prevention

## Configuration

### Enable WAF
```hcl
enable_waf = true
create_test_instances = true  # Required for target groups
```

### Rate Limiting
```hcl
waf_rate_limit = 2000  # Requests per 5 minutes per IP
```

### Geographic Blocking
```hcl
waf_blocked_countries = ["CN", "RU", "KP", "IR"]
```

### IP Allow/Block Lists
```hcl
waf_allowed_ips = [
  "203.0.113.0/24",    # Your office network
  "198.51.100.0/24"    # Your datacenter
]

waf_blocked_ips = [
  "192.0.2.0/24"       # Known malicious network
]
```

### AWS Managed Rules
```hcl
enable_aws_managed_rules = {
  core_rule_set           = true   # Recommended
  admin_protection        = true   # For admin panels
  known_bad_inputs        = true   # General protection
  sql_injection          = true   # Database protection
  linux_operating_system = true   # OS-specific rules
  unix_operating_system  = false  # If using Unix systems
}
```

## Accessing Your Applications

After deployment, access your applications via:

- **Shared VPC**: `http://<ALB_DNS_NAME>/shared`
- **Spoke1 VPC**: `http://<ALB_DNS_NAME>/spoke1`
- **Spoke2 VPC**: `http://<ALB_DNS_NAME>/spoke2`

The ALB DNS name will be in the Terraform outputs.

## Monitoring and Logging

### CloudWatch Metrics
WAF automatically creates CloudWatch metrics for:
- Total requests
- Allowed/blocked requests per rule
- Rate limit violations
- Geographic blocks

### WAF Logs
- Stored in CloudWatch Logs: `aws-waf-logs-<project_name>`
- Retention: 30 days
- Encrypted with KMS
- Redacted sensitive headers (authorization, cookie)

### Useful CloudWatch Queries

#### Top Blocked IPs
```sql
fields @timestamp, httpRequest.clientIP, terminatingRuleId
| filter action = "BLOCK"
| stats count() by httpRequest.clientIP
| sort count desc
| limit 20
```

#### Geographic Distribution
```sql
fields @timestamp, httpRequest.country
| filter action = "ALLOW"
| stats count() by httpRequest.country
| sort count desc
```

#### Rate Limit Violations
```sql
fields @timestamp, httpRequest.clientIP, terminatingRuleId
| filter terminatingRuleId = "RateLimitRule"
| sort @timestamp desc
```

## Security Best Practices

### 1. Start with Monitoring Mode
Initially deploy with all rules in COUNT mode to understand traffic patterns:

```hcl
# In your WAF rules, change:
action {
  count {}  # Instead of block {}
}
```

### 2. Gradual Rule Enablement
Enable rules progressively:
1. Start with rate limiting
2. Add geographic blocking
3. Enable AWS managed rules
4. Add custom rules

### 3. IP Allowlist Strategy
- Add your office/admin IPs to allowlist
- Use narrow CIDR ranges
- Regularly review and update

### 4. Rate Limiting Guidelines
- **2000 req/5min**: Good default for most applications
- **500 req/5min**: Strict limit for sensitive applications  
- **5000 req/5min**: Relaxed limit for high-traffic sites

### 5. Geographic Blocking Considerations
- Review your user base geographic distribution
- Consider impact on legitimate users
- Use country codes carefully (some users may use VPNs)

## Troubleshooting

### Common Issues

#### 1. Legitimate Traffic Blocked
**Symptoms**: Users report access denied
**Solution**:
- Check CloudWatch logs for blocked requests
- Add legitimate IPs to allowlist
- Adjust rate limits
- Review rule priorities

#### 2. Rule Conflicts
**Symptoms**: Unexpected blocking behavior
**Solution**:
- Review rule priorities (lower number = higher priority)
- Check rule logic and conditions
- Use CloudWatch metrics to identify conflicting rules

#### 3. High False Positives
**Symptoms**: Many legitimate requests blocked
**Solution**:
- Switch problematic rules to COUNT mode temporarily
- Fine-tune rule conditions
- Consider using rule group overrides

### Testing WAF Rules

#### Test Rate Limiting
```bash
# Generate rapid requests to trigger rate limit
for i in {1..100}; do
  curl -s http://<ALB_DNS_NAME>/shared
  sleep 0.1
done
```

#### Test Geographic Blocking
Use a VPN service to test from blocked countries.

#### Test Custom Rules
```bash
# Test SQL injection detection
curl -X POST http://<ALB_DNS_NAME>/shared \
  -d "user_input=' OR 1=1--"

# Test XSS detection  
curl -X POST http://<ALB_DNS_NAME>/shared \
  -d "comment=<script>alert('xss')</script>"
```

## Cost Considerations

### WAF Pricing (approximate)
- **Web ACL**: $1.00/month
- **Rules**: $0.60/month per rule
- **Requests**: $0.60 per million requests
- **CloudWatch Logs**: $0.50/GB ingested

### Optimization Tips
- Use managed rule groups (more cost-effective than custom rules)
- Set appropriate log retention periods
- Monitor usage and adjust rules based on actual traffic

## Advanced Configurations

### Custom Rule Examples

#### Block Specific User Agents
```hcl
rule {
  name     = "BlockBadUserAgents"
  priority = 15

  statement {
    byte_match_statement {
      search_string = "BadBot"
      field_to_match {
        single_header {
          name = "user-agent"
        }
      }
      text_transformation {
        priority = 0
        type     = "LOWERCASE"
      }
      positional_constraint = "CONTAINS"
    }
  }

  action {
    block {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                 = "BlockBadUserAgents"
    sampled_requests_enabled    = true
  }
}
```

#### Size Restriction
```hcl
rule {
  name     = "SizeRestriction"
  priority = 16

  statement {
    size_constraint_statement {
      field_to_match {
        body {}
      }
      comparison_operator = "GT"
      size                = 8192  # 8KB limit
      text_transformation {
        priority = 0
        type     = "NONE"
      }
    }
  }

  action {
    block {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                 = "SizeRestriction"
    sampled_requests_enabled    = true
  }
}
```

## Maintenance

### Regular Tasks
1. **Review CloudWatch metrics weekly**
2. **Update IP allowlists/blocklists monthly**
3. **Review rule effectiveness quarterly**
4. **Update managed rule groups (automatic)**

### Monitoring Alerts
Set up CloudWatch alarms for:
- High block rates (potential attack)
- Unusual geographic patterns
- Rate limit violations
- Rule evaluation errors

This WAF implementation provides comprehensive protection for your hub-spoke web applications while maintaining flexibility and observability. 