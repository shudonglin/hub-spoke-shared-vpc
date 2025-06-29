# ===============================
# Application Load Balancer
# ===============================

# Security group for ALB (in Spoke1 VPC)
resource "aws_security_group" "alb_sg" {
  count       = var.enable_waf ? 1 : 0
  name_prefix = "${var.project_name}-spoke1-alb-"
  description = "Security group for Application Load Balancer in Spoke1 VPC"
  vpc_id      = aws_vpc.vpcs["spoke1"].id  # ALB now in spoke1 VPC

  # Allow HTTP from anywhere
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTPS from anywhere
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-spoke1-alb-sg"
  })
}

# Application Load Balancer (in Spoke1 VPC)
resource "aws_lb" "main" {
  count              = var.enable_waf ? 1 : 0
  name               = "${var.project_name}-spoke1-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg[0].id]
  
  # Place ALB in spoke1 public subnets across multiple AZs
  subnets = [
    for az_index in range(length(local.azs)) :
    aws_subnet.public_subnets["spoke1-public-${az_index}"].id
  ]

  enable_deletion_protection = false

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-spoke1-alb"
  })
}

# Target group for spoke1 instance (simplified - no cross-VPC routing needed)
resource "aws_lb_target_group" "spoke1_app" {
  count = var.enable_waf && var.create_test_instances && contains(var.test_instance_vpcs, "spoke1") ? 1 : 0
  
  name        = "${var.project_name}-spoke1-app-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpcs["spoke1"].id  # Target group in same VPC as ALB
  target_type = "instance"  # Direct instance targeting (more efficient)

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5          # Reduced timeout (no cross-VPC latency)
    unhealthy_threshold = 2          # Faster failure detection
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-spoke1-app-tg"
    Purpose = "App1 Web Server"
  })
}

# Target group attachment for spoke1 instance
resource "aws_lb_target_group_attachment" "spoke1_app" {
  count = var.enable_waf && var.create_test_instances && contains(var.test_instance_vpcs, "spoke1") ? 1 : 0

  target_group_arn = aws_lb_target_group.spoke1_app[0].arn
  target_id        = aws_instance.test_instances["spoke1"].id  # Direct instance ID
  port             = 80
}

# ALB Listener (HTTP) - Simple routing to spoke1 app
resource "aws_lb_listener" "main" {
  count             = var.enable_waf ? 1 : 0
  load_balancer_arn = aws_lb.main[0].arn
  port              = "80"
  protocol          = "HTTP"

  # Default action - forward all traffic to spoke1 app
  default_action {
    type             = "forward"
    target_group_arn = var.create_test_instances && contains(var.test_instance_vpcs, "spoke1") ? aws_lb_target_group.spoke1_app[0].arn : null
  }
}

# Note: Security group rules for HTTP access to spoke1 instance are already defined in main.tf
# The spoke1 instance security group allows HTTP access from spoke1 VPC (where ALB is located)
# Spoke2 instance is completely independent (no ALB access)

# ===============================
# AWS WAF Web ACL
# ===============================

# IP Set for allowed IPs
resource "aws_wafv2_ip_set" "allowed_ips" {
  count              = var.enable_waf && length(var.waf_allowed_ips) > 0 ? 1 : 0
  name               = "${var.project_name}-allowed-ips"
  description        = "IP addresses always allowed"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"

  addresses = var.waf_allowed_ips

  tags = local.common_tags
}

# IP Set for blocked IPs
resource "aws_wafv2_ip_set" "blocked_ips" {
  count              = var.enable_waf && length(var.waf_blocked_ips) > 0 ? 1 : 0
  name               = "${var.project_name}-blocked-ips"
  description        = "IP addresses to block"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"

  addresses = var.waf_blocked_ips

  tags = local.common_tags
}

# Main WAF Web ACL
resource "aws_wafv2_web_acl" "main" {
  count       = var.enable_waf ? 1 : 0
  name        = "${var.project_name}-web-acl"
  description = "WAF rules for hub-spoke web applications"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1: Allow specific IPs (highest priority)
  dynamic "rule" {
    for_each = length(var.waf_allowed_ips) > 0 ? [1] : []
    content {
      name     = "AllowSpecificIPs"
      priority = 1

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.allowed_ips[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                 = "AllowSpecificIPs"
        sampled_requests_enabled    = true
      }

      action {
        allow {}
      }
    }
  }

  # Rule 2: Block specific IPs
  dynamic "rule" {
    for_each = length(var.waf_blocked_ips) > 0 ? [1] : []
    content {
      name     = "BlockSpecificIPs"
      priority = 2

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.blocked_ips[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                 = "BlockSpecificIPs"
        sampled_requests_enabled    = true
      }

      action {
        block {}
      }
    }
  }

  # Rule 3: Geographic blocking
  dynamic "rule" {
    for_each = length(var.waf_blocked_countries) > 0 ? [1] : []
    content {
      name     = "BlockCountries"
      priority = 3

      statement {
        geo_match_statement {
          country_codes = var.waf_blocked_countries
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                 = "BlockCountries"
        sampled_requests_enabled    = true
      }

      action {
        block {}
      }
    }
  }

  # Rule 4: Rate limiting
  rule {
    name     = "RateLimitRule"
    priority = 10

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "RateLimitRule"
      sampled_requests_enabled    = true
    }

    action {
      block {}
    }
  }

  # Rule 5: AWS Managed Core Rule Set
  dynamic "rule" {
    for_each = var.enable_aws_managed_rules.core_rule_set ? [1] : []
    content {
      name     = "AWSManagedRulesCommonRuleSet"
      priority = 20

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesCommonRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                 = "CommonRuleSetMetric"
        sampled_requests_enabled    = true
      }
    }
  }

  # Rule 6: Admin Protection
  dynamic "rule" {
    for_each = var.enable_aws_managed_rules.admin_protection ? [1] : []
    content {
      name     = "AWSManagedRulesAdminProtectionRuleSet"
      priority = 21

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesAdminProtectionRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                 = "AdminProtectionRuleSetMetric"
        sampled_requests_enabled    = true
      }
    }
  }

  # Rule 7: Known Bad Inputs
  dynamic "rule" {
    for_each = var.enable_aws_managed_rules.known_bad_inputs ? [1] : []
    content {
      name     = "AWSManagedRulesKnownBadInputsRuleSet"
      priority = 22

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesKnownBadInputsRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                 = "KnownBadInputsRuleSetMetric"
        sampled_requests_enabled    = true
      }
    }
  }

  # Rule 8: SQL Injection Protection
  dynamic "rule" {
    for_each = var.enable_aws_managed_rules.sql_injection ? [1] : []
    content {
      name     = "AWSManagedRulesSQLiRuleSet"
      priority = 23

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesSQLiRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                 = "SQLiRuleSetMetric"
        sampled_requests_enabled    = true
      }
    }
  }

  # Rule 9: Linux Operating System Protection
  dynamic "rule" {
    for_each = var.enable_aws_managed_rules.linux_operating_system ? [1] : []
    content {
      name     = "AWSManagedRulesLinuxRuleSet"
      priority = 24

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesLinuxRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                 = "LinuxRuleSetMetric"
        sampled_requests_enabled    = true
      }
    }
  }

  # Rule 10: Custom SQL Injection Rule (example)
  rule {
    name     = "CustomSQLInjectionRule"
    priority = 30

    statement {
      sqli_match_statement {
        field_to_match {
          body {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "CustomSQLInjectionRule"
      sampled_requests_enabled    = true
    }

    action {
      block {}
    }
  }

  # Rule 11: Custom XSS Protection
  rule {
    name     = "CustomXSSRule"
    priority = 31

    statement {
      xss_match_statement {
        field_to_match {
          body {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "CustomXSSRule"
      sampled_requests_enabled    = true
    }

    action {
      block {}
    }
  }

  tags = local.common_tags

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                 = "${var.project_name}WebAcl"
    sampled_requests_enabled    = true
  }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "main" {
  count        = var.enable_waf ? 1 : 0
  resource_arn = aws_lb.main[0].arn
  web_acl_arn  = aws_wafv2_web_acl.main[0].arn
}

# ===============================
# CloudWatch Logging for WAF
# ===============================

resource "aws_cloudwatch_log_group" "waf_log_group" {
  count             = var.enable_waf ? 1 : 0
  name              = "aws-waf-logs-${var.project_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.vpc_flow_logs_key[0].arn

  tags = local.common_tags
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count                   = var.enable_waf ? 1 : 0
  resource_arn            = aws_wafv2_web_acl.main[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_log_group[0].arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
} 