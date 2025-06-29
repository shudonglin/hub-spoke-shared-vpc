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
        "ping test-${vpc}.${var.domain_name}",
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
      "# Test connectivity from spoke2 to spoke1:",
      "ping -c 3 test-spoke1.${var.domain_name}",
      "curl http://test-spoke1.${var.domain_name}",
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
  description = "URLs to access web applications through ALB"
  value = var.enable_waf && var.create_test_instances ? {
    main_app = "http://${aws_lb.main[0].dns_name}"
    health_check = "http://${aws_lb.main[0].dns_name}/health"
    waf_testing = {
      admin_panel = "http://${aws_lb.main[0].dns_name}/admin"
      sql_injection = "http://${aws_lb.main[0].dns_name}/test-sql?id=1' OR '1'='1"
      xss_test = "http://${aws_lb.main[0].dns_name}/test-xss"
    }
    spoke2_access = var.enable_spoke2_alb_access && contains(var.test_instance_vpcs, "spoke2") ? {
      path_based = "http://${aws_lb.main[0].dns_name}/spoke2"
      secondary_path = "http://${aws_lb.main[0].dns_name}/test2"
      note = "Spoke2 accessible via ALB with path-based routing"
    } : null
    spoke2_note = var.enable_spoke2_alb_access && contains(var.test_instance_vpcs, "spoke2") ? null : "Spoke2 ALB access disabled - use direct DNS or enable via enable_spoke2_alb_access=true"
  } : null
}

output "direct_instance_access" {
  description = "Direct access to instances (not through ALB)"
  value = var.create_test_instances ? {
    spoke1_nginx = {
      description = "Nginx web server (also behind ALB)"
      dns_name = "test-spoke1.${var.domain_name}"
      private_ip = aws_instance.test_instances["spoke1"].private_ip
      note = "Available via ALB and direct DNS"
    }
    spoke2_test = {
      description = "Independent test instance (not behind ALB)"
      dns_name = "test-spoke2.${var.domain_name}"
      private_ip = aws_instance.test_instances["spoke2"].private_ip
      note = "Used for connectivity and DNS testing only"
    }
  } : null
}

output "architecture_summary" {
  description = "Summary of the deployed architecture"
  value = var.enable_waf && var.create_test_instances ? {
    alb_location = "Shared VPC (centralized)"
    web_server = "Spoke1: Nginx behind ALB (private subnet) - Primary"
    test_instance = var.enable_spoke2_alb_access ? "Spoke2: Optional ALB routing + independent access" : "Spoke2: Independent test instance only"
    waf_protection = "Enabled with OWASP Top 10 + custom rules"
    routing = var.enable_spoke2_alb_access ? "ALB → Transit Gateway → Spoke1 (default) & Spoke2 (optional paths)" : "ALB → Transit Gateway → Spoke1 VPC only"
    health_checks = var.enable_spoke2_alb_access ? "ALB health checks to both spoke1 and spoke2" : "ALB health checks via Transit Gateway to spoke1"
    spoke2_alb_access = var.enable_spoke2_alb_access ? "Enabled (paths: /spoke2*, /test2*, /secondary*)" : "Disabled (direct DNS only)"
    spoke2_purpose = "DNS resolution, connectivity testing, and optional web serving"
  } : null
} 