output "vpc_ids" {
  description = "Map of VPC names to IDs"
  value = {
    for k, v in aws_vpc.vpcs : k => v.id
  }
}

output "vpc_cidrs" {
  description = "Map of VPC names to CIDR blocks"
  value = {
    for k, v in local.vpcs : k => v.cidr
  }
}

output "public_subnet_ids" {
  description = "Map of public subnet identifiers to IDs"
  value = {
    for k, v in aws_subnet.public_subnets : k => v.id
  }
}

output "private_subnet_ids" {
  description = "Map of private subnet identifiers to IDs"
  value = {
    for k, v in aws_subnet.private_subnets : k => v.id
  }
}

output "database_subnet_ids" {
  description = "Map of database subnet identifiers to IDs"
  value = {
    for k, v in aws_subnet.database_subnets : k => v.id
  }
}

output "tgw_subnet_ids" {
  description = "Map of Transit Gateway subnet identifiers to IDs"
  value = {
    for k, v in aws_subnet.tgw_subnets : k => v.id
  }
}

output "transit_gateway_id" {
  description = "ID of the Transit Gateway"
  value       = aws_ec2_transit_gateway.tgw.id
}

output "transit_gateway_route_table_ids" {
  description = "Map of Transit Gateway route table names to IDs"
  value = {
    shared = aws_ec2_transit_gateway_route_table.shared_rt.id
    spoke  = aws_ec2_transit_gateway_route_table.spoke_rt.id
  }
}

output "nat_gateway_ids" {
  description = "Map of NAT Gateway identifiers to IDs"
  value = {
    for k, v in aws_nat_gateway.nat_gws : k => v.id
  }
}

output "internet_gateway_ids" {
  description = "Map of Internet Gateway VPC names to IDs"
  value = {
    for k, v in aws_internet_gateway.igws : k => v.id
  }
}

output "route53_private_zone_id" {
  description = "ID of the Route53 private hosted zone"
  value       = aws_route53_zone.private_zone.zone_id
}

output "route53_private_zone_name" {
  description = "Name of the Route53 private hosted zone"
  value       = aws_route53_zone.private_zone.name
}

output "route53_resolver_endpoint_ids" {
  description = "Map of Route53 resolver endpoint names to IDs"
  value = {
    inbound  = aws_route53_resolver_endpoint.inbound.id
    outbound = aws_route53_resolver_endpoint.outbound.id
  }
}

output "vpc_endpoint_ids" {
  description = "Map of VPC endpoint names to IDs"
  value = {
    s3       = aws_vpc_endpoint.s3.id
    dynamodb = aws_vpc_endpoint.dynamodb.id
  }
}

output "security_group_ids" {
  description = "Map of security group names to IDs"
  value = merge(
    {
      resolver_sg = aws_security_group.resolver_sg.id
    },
    var.create_test_instances ? {
      for k, v in aws_security_group.test_instance_sg : k => v.id
    } : {}
  )
}

output "availability_zones" {
  description = "List of availability zones used"
  value       = local.azs
}

output "vpc_flow_logs" {
  description = "VPC Flow Logs information"
  value = var.enable_vpc_flow_logs ? {
    kms_key_id = aws_kms_key.vpc_flow_logs_key[0].id
    kms_key_arn = aws_kms_key.vpc_flow_logs_key[0].arn
    kms_alias = aws_kms_alias.vpc_flow_logs_key_alias[0].name
    iam_role_arn = aws_iam_role.vpc_flow_logs_role[0].arn
    log_groups = {
      for k, v in aws_cloudwatch_log_group.vpc_flow_logs : k => {
        name = v.name
        arn = v.arn
      }
    }
    flow_logs = {
      for k, v in aws_flow_log.vpc_flow_logs : k => v.id
    }
  } : null
}

output "test_instances" {
  description = "Test instances information"
  value = var.create_test_instances ? {
    for vpc in var.test_instance_vpcs : vpc => {
      id              = aws_instance.test_instances[vpc].id
      private_ip      = aws_instance.test_instances[vpc].private_ip
      vpc             = vpc
      dns_name        = "test-${vpc}.${var.domain_name}"
      ssh_command     = "aws ssm start-session --target ${aws_instance.test_instances[vpc].id}"
      test_url        = "http://${aws_instance.test_instances[vpc].private_ip}"
      connectivity_script = "/home/ec2-user/test-connectivity.sh"
      connectivity_tests = [
        "# ICMP ping disabled for security - use HTTP tests instead",
        "curl http://test-${vpc}.${var.domain_name}",
        "nslookup test-${vpc}.${var.domain_name}",
        "# Run comprehensive connectivity test:",
        "sudo -u ec2-user /home/ec2-user/test-connectivity.sh"
      ]
    }
  } : {}
}

output "connectivity_test_commands" {
  description = "Commands to test connectivity from spoke2 to spoke1 (and DNS resolution)"
  value = var.create_test_instances && length(var.test_instance_vpcs) > 1 ? {
    test_from_spoke2 = [
      "# Connect to spoke2 test instance:",
      "aws ssm start-session --target ${var.create_test_instances ? aws_instance.test_instances["spoke2"].id : "<SPOKE2_INSTANCE_ID>"}",
      "",
      "# Test DNS resolution from spoke2:",
      "nslookup test-spoke1.${var.domain_name}",
      "nslookup test-spoke2.${var.domain_name}",
      "",
      "# Test connectivity from spoke2 to spoke1 (ICMP ping disabled):",
      "# ping test disabled in security groups - use HTTP instead:",
      "curl http://test-spoke1.${var.domain_name}",
      "nc -zv test-spoke1.${var.domain_name} 80",
      "",
      "# Run comprehensive connectivity test script:",
      "sudo -u ec2-user /home/ec2-user/test-connectivity.sh"
    ]
    web_access_tests = [
      "# Test ALB access (external):",
      "curl http://${var.enable_waf ? aws_lb.main[0].dns_name : "<ALB_DNS_NAME>"}",
      "",
      "# Test direct access to spoke1 (from within VPC):",
      "curl http://test-spoke1.${var.domain_name}",
      "",
      "# DNS troubleshooting (if needed):",
      "bash fix-dns.sh",
      "bash dns-troubleshoot.sh"
    ]
  } : null
}

output "bastion_host" {
  description = "Bastion host information"
  value = var.create_bastion_host ? {
    id          = aws_instance.bastion[0].id
    public_ip   = aws_eip.bastion_eip[0].public_ip
    private_ip  = aws_instance.bastion[0].private_ip
    dns_name    = "bastion.${var.domain_name}"
    ssh_command = "ssh -i ~/.ssh/your-key.pem ec2-user@${aws_eip.bastion_eip[0].public_ip}"
    usage_info = [
      "# SSH to bastion host:",
      "ssh -i ~/.ssh/your-key.pem ec2-user@${aws_eip.bastion_eip[0].public_ip}",
      "",
      "# From bastion, SSH to test instances:",
      "ssh ec2-user@test-spoke1.${var.domain_name}",
      "ssh ec2-user@test-spoke2.${var.domain_name}",
      "",
      "# Or use SSM from bastion:",
      "aws ssm start-session --target <INSTANCE_ID>"
    ]
  } : null
}

# ===============================
# WAF Outputs
# ===============================

# ===============================
# DNS Records and ALB Information
# ===============================

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = var.enable_waf ? aws_lb.main[0].dns_name : null
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = var.enable_waf ? aws_lb.main[0].zone_id : null
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = var.enable_waf ? aws_lb.main[0].arn : null
}

output "route53_dns_records" {
  description = "Route53 DNS records for EC2 instances"
  value = var.create_test_instances ? {
    spoke1_instance = {
      dns_name = "test-spoke1.${var.domain_name}"
      private_ip = aws_instance.test_instances["spoke1"].private_ip
      record_type = "A"
      vpc_location = "Spoke1 VPC"
      description = "Nginx web server behind ALB"
    }
    spoke2_instance = {
      dns_name = "test-spoke2.${var.domain_name}"
      private_ip = aws_instance.test_instances["spoke2"].private_ip
      record_type = "A" 
      vpc_location = "Spoke2 VPC"
      description = "Independent Apache test server"
    }
    private_zone = {
      zone_name = var.domain_name
      zone_id = aws_route53_zone.private_zone.zone_id
      description = "Private hosted zone for cross-VPC DNS resolution"
    }
  } : null
}

output "dns_and_alb_summary" {
  description = "Complete DNS and ALB access summary"
  value = var.enable_waf && var.create_test_instances ? {
    alb_access = {
      url = "http://${aws_lb.main[0].dns_name}"
      dns_name = aws_lb.main[0].dns_name
      location = "Spoke1 VPC"
      targets = "App1 (Nginx) only"
    }
    route53_records = {
      app1_dns = "test-spoke1.${var.domain_name} → ${aws_instance.test_instances["spoke1"].private_ip}"
      app2_dns = "test-spoke2.${var.domain_name} → ${aws_instance.test_instances["spoke2"].private_ip}" 
      zone = "${var.domain_name} (${aws_route53_zone.private_zone.zone_id})"
    }
    access_methods = {
      app1_via_alb = "http://${aws_lb.main[0].dns_name} (with WAF protection)"
      app1_direct = "http://test-spoke1.${var.domain_name} (internal access)"
      app2_direct = "http://test-spoke2.${var.domain_name} (internal access only)"
    }
  } : null
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = var.enable_waf ? aws_wafv2_web_acl.main[0].arn : null
}

output "waf_web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = var.enable_waf ? aws_wafv2_web_acl.main[0].id : null
}

output "waf_cloudwatch_log_group" {
  description = "CloudWatch log group for WAF logs"
  value       = var.enable_waf ? aws_cloudwatch_log_group.waf_log_group[0].name : null
}

output "web_application_urls" {
  description = "URLs to access App1 through ALB (in Spoke1 VPC)"
  value = var.enable_waf && var.create_test_instances ? {
    app1_main = "http://${aws_lb.main[0].dns_name}"
    app1_health = "http://${aws_lb.main[0].dns_name}/health"
    waf_testing = {
      admin_panel = "http://${aws_lb.main[0].dns_name}/admin"
      sql_injection = "http://${aws_lb.main[0].dns_name}/test-sql?id=1' OR '1'='1"
      xss_test = "http://${aws_lb.main[0].dns_name}/test-xss"
    }
    note = "ALB located in Spoke1 VPC - direct access to App1 only"
  } : null
}

output "direct_instance_access" {
  description = "Direct access to instances"
  value = var.create_test_instances ? {
    app1_spoke1 = {
      description = "App1 - Nginx web server behind ALB in Spoke1 VPC"
      dns_name = "test-spoke1.${var.domain_name}"
      private_ip = aws_instance.test_instances["spoke1"].private_ip
      alb_access = "Available via ALB and direct DNS"
      location = "Spoke1 VPC"
    }
    app2_spoke2 = {
      description = "App2 - Independent instance in Spoke2 VPC"
      dns_name = "test-spoke2.${var.domain_name}"
      private_ip = aws_instance.test_instances["spoke2"].private_ip
      alb_access = "No ALB - direct DNS access only"
      location = "Spoke2 VPC"
      note = "Completely independent from App1 ALB"
    }
  } : null
}

output "architecture_summary" {
  description = "Summary of the deployed architecture"
  value = var.enable_waf && var.create_test_instances ? {
    alb_location = "Spoke1 VPC (distributed architecture)"
    app1_spoke1 = "Nginx web server behind ALB in Spoke1 VPC"
    app2_spoke2 = "Independent Apache test server in Spoke2 VPC (no ALB)"
    waf_protection = "Centralized WAF rules applied to Spoke1 ALB"
    routing = "Direct ALB → Spoke1 instance (same VPC)"
    health_checks = "Direct ALB health checks to Spoke1 instance"
    spoke2_access = "Direct DNS only - completely independent"
    architecture_type = "Distributed ALB with centralized WAF"
    benefits = "Better performance, isolation, no cross-VPC routing latency"
  } : null
}

# ===============================
# Enhanced Monitoring Outputs
# ===============================

output "monitoring_dashboard" {
  description = "CloudWatch Dashboard for infrastructure monitoring"
  value = var.enable_enhanced_monitoring ? {
    dashboard_name = aws_cloudwatch_dashboard.main[0].dashboard_name
    dashboard_url = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.main[0].dashboard_name}"
  } : null
}

output "cloudwatch_alarms" {
  description = "CloudWatch alarms for monitoring"
  value = var.enable_enhanced_monitoring ? {
    cpu_alarms = var.create_test_instances ? {
      for vpc in var.test_instance_vpcs : vpc => aws_cloudwatch_metric_alarm.high_cpu[vpc].alarm_name
    } : {}
    memory_alarms = var.create_test_instances ? {
      for vpc in var.test_instance_vpcs : vpc => aws_cloudwatch_metric_alarm.high_memory[vpc].alarm_name
    } : {}
    alb_response_time_alarm = var.enable_waf ? aws_cloudwatch_metric_alarm.alb_response_time[0].alarm_name : null
  } : null
}

output "sns_topic" {
  description = "SNS topic for alerts"
  value = var.enable_sns_alerts ? {
    topic_arn = aws_sns_topic.alerts[0].arn
    topic_name = aws_sns_topic.alerts[0].name
    email_subscription = var.sns_alert_email != "" ? "Email alerts configured" : "No email configured - add to terraform.tfvars"
  } : null
}

# ===============================
# Security Monitoring Outputs
# ===============================

output "cloudtrail" {
  description = "CloudTrail configuration for API auditing"
  value = var.enable_cloudtrail ? {
    trail_name = aws_cloudtrail.main[0].name
    trail_arn = aws_cloudtrail.main[0].arn
    s3_bucket = aws_s3_bucket.cloudtrail[0].bucket
    console_url = "https://${var.aws_region}.console.aws.amazon.com/cloudtrail/home?region=${var.aws_region}#/trails/${aws_cloudtrail.main[0].arn}"
  } : null
}

output "config_service" {
  description = "AWS Config for configuration monitoring"
  value = var.enable_config ? {
    recorder_name = aws_config_configuration_recorder.main[0].name
    delivery_channel = aws_config_delivery_channel.main[0].name
    s3_bucket = aws_s3_bucket.config[0].bucket
    console_url = "https://${var.aws_region}.console.aws.amazon.com/config/home?region=${var.aws_region}#/dashboard"
  } : null
}

output "guardduty" {
  description = "GuardDuty security monitoring"
  value = var.enable_guardduty ? {
    detector_id = aws_guardduty_detector.main[0].id
    console_url = "https://${var.aws_region}.console.aws.amazon.com/guardduty/home?region=${var.aws_region}#/findings"
    status = "GuardDuty enabled with malware protection and S3 logs"
  } : null
}

# ===============================
# Enhanced Security Outputs
# ===============================

output "enhanced_security_features" {
  description = "Enhanced security features deployed"
  value = var.enable_enhanced_security ? {
    network_acls = "Deployed on all VPCs for additional security layer"
    vpc_endpoints = var.enable_vpc_endpoints ? {
      ssm_endpoints = "SSM endpoints deployed in all VPCs for secure management (~$63-135/month)"
      s3_gateway = "S3 gateway endpoint deployed"
      dynamodb_gateway = "DynamoDB gateway endpoint deployed"
    } : {
      ssm_access = "SSM access via NAT Gateway (cost-optimized)"
      s3_gateway = "S3 gateway endpoint deployed"
      dynamodb_gateway = "DynamoDB gateway endpoint deployed"
    }
    security_groups = {
      database_tier = "Database security groups with restricted access"
      management = "Management security group for admin access"
      vpc_endpoints = var.enable_vpc_endpoints ? "VPC endpoint security groups deployed" : "VPC endpoint security groups disabled (cost optimization)"
    }
  } : null
}

output "vpn_gateway" {
  description = "VPN Gateway information"
  value = var.enable_vpn_gateway ? {
    vpn_gateway_id = aws_vpn_gateway.main[0].id
    status = "VPN Gateway attached to shared VPC"
    note = "Configure customer gateway and VPN connection separately"
  } : null
}

# ===============================
# Security & Compliance Summary
# ===============================

output "security_compliance_summary" {
  description = "Summary of security and compliance features"
  value = {
    monitoring = {
      vpc_flow_logs = var.enable_vpc_flow_logs ? "✅ Enabled" : "❌ Disabled"
      cloudwatch_monitoring = var.enable_enhanced_monitoring ? "✅ Enabled" : "❌ Disabled"
      sns_alerts = var.enable_sns_alerts ? "✅ Enabled" : "❌ Disabled"
    }
    auditing = {
      cloudtrail = var.enable_cloudtrail ? "✅ Enabled" : "❌ Disabled"
      config = var.enable_config ? "✅ Enabled" : "❌ Disabled"
    }
    security = {
      waf = var.enable_waf ? "✅ Enabled" : "❌ Disabled"
      guardduty = var.enable_guardduty ? "✅ Enabled" : "❌ Disabled"
      enhanced_security = var.enable_enhanced_security ? "✅ Enabled" : "❌ Disabled"
      icmp_disabled = "✅ ICMP ping disabled in security groups"
    }
    encryption = {
      vpc_flow_logs = var.enable_vpc_flow_logs ? "✅ KMS encrypted" : "❌ Not applicable"
      cloudtrail = var.enable_cloudtrail ? "✅ KMS encrypted" : "❌ Not applicable"
      s3_buckets = "✅ Server-side encryption enabled"
    }
    cost_optimization = {
      single_nat_gateway = var.single_nat_gateway ? "✅ Enabled (~$135/month savings)" : "❌ Disabled"
      bastion_host = var.create_bastion_host ? "❌ Enabled (~$8/month cost)" : "✅ Disabled (using SSM)"
    }
  }
} 