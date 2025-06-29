# ===============================
# AWS CloudWatch Monitoring
# ===============================

# CloudWatch Log Groups for centralized logging
resource "aws_cloudwatch_log_group" "application_logs" {
  for_each = var.create_test_instances ? toset(var.test_instance_vpcs) : toset([])
  
  name              = "/aws/ec2/${var.project_name}-${each.key}-app"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = var.enable_vpc_flow_logs ? aws_kms_key.vpc_flow_logs_key[0].arn : null

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.key}-app-logs"
    Type = "ApplicationLogs"
  })
}

# CloudWatch Log Group for System Logs
resource "aws_cloudwatch_log_group" "system_logs" {
  count = var.enable_enhanced_monitoring ? 1 : 0
  
  name              = "/aws/ec2/${var.project_name}-system"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = var.enable_vpc_flow_logs ? aws_kms_key.vpc_flow_logs_key[0].arn : null

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-system-logs"
    Type = "SystemLogs"
  })
}

# CloudWatch Alarms for EC2 Instances
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  for_each = var.create_test_instances && var.enable_enhanced_monitoring ? toset(var.test_instance_vpcs) : toset([])

  alarm_name          = "${var.project_name}-${each.key}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = var.enable_sns_alerts ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    InstanceId = aws_instance.test_instances[each.key].id
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.key}-cpu-alarm"
  })
}

# CloudWatch Alarms for Memory Usage (requires CloudWatch agent)
resource "aws_cloudwatch_metric_alarm" "high_memory" {
  for_each = var.create_test_instances && var.enable_enhanced_monitoring ? toset(var.test_instance_vpcs) : toset([])

  alarm_name          = "${var.project_name}-${each.key}-high-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "mem_used_percent"
  namespace           = "CWAgent"
  period              = "300"
  statistic           = "Average"
  threshold           = "85"
  alarm_description   = "This metric monitors memory utilization"
  alarm_actions       = var.enable_sns_alerts ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    InstanceId = aws_instance.test_instances[each.key].id
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.key}-memory-alarm"
  })
}

# CloudWatch Alarms for ALB
resource "aws_cloudwatch_metric_alarm" "alb_response_time" {
  count = var.enable_waf && var.enable_enhanced_monitoring ? 1 : 0

  alarm_name          = "${var.project_name}-alb-high-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "This metric monitors ALB response time"
  alarm_actions       = var.enable_sns_alerts ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    LoadBalancer = aws_lb.main[0].arn_suffix
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-alb-response-time-alarm"
  })
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "main" {
  count = var.enable_enhanced_monitoring ? 1 : 0
  
  dashboard_name = "${var.project_name}-infrastructure"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            for vpc in var.test_instance_vpcs : [
              "AWS/EC2",
              "CPUUtilization",
              "InstanceId",
              var.create_test_instances ? aws_instance.test_instances[vpc].id : ""
            ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "EC2 CPU Utilization"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = var.enable_waf ? [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.main[0].arn_suffix],
            [".", "TargetResponseTime", ".", "."],
            [".", "HTTPCode_Target_2XX_Count", ".", "."],
            [".", "HTTPCode_Target_4XX_Count", ".", "."],
            [".", "HTTPCode_Target_5XX_Count", ".", "."]
          ] : []
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Application Load Balancer Metrics"
          period  = 300
        }
      }
    ]
  })
}

# ===============================
# SNS for Alerts
# ===============================

resource "aws_sns_topic" "alerts" {
  count = var.enable_sns_alerts ? 1 : 0
  name  = "${var.project_name}-alerts"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-alerts-topic"
  })
}

resource "aws_sns_topic_policy" "alerts" {
  count = var.enable_sns_alerts ? 1 : 0
  arn   = aws_sns_topic.alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts[0].arn
      }
    ]
  })
}

# Email subscription for alerts (optional)
resource "aws_sns_topic_subscription" "email_alerts" {
  count     = var.enable_sns_alerts && var.sns_alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.sns_alert_email
}

# ===============================
# AWS CloudTrail for API Auditing
# ===============================

# S3 bucket for CloudTrail
resource "aws_s3_bucket" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = "${var.project_name}-cloudtrail-${random_id.bucket_suffix[0].hex}"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-cloudtrail"
  })
}

resource "random_id" "bucket_suffix" {
  count       = var.enable_cloudtrail ? 1 : 0
  byte_length = 8
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.enable_vpc_flow_logs ? aws_kms_key.vpc_flow_logs_key[0].arn : null
      sse_algorithm     = var.enable_vpc_flow_logs ? "aws:kms" : "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.project_name}-trail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail[0].arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.project_name}-trail"
          }
        }
      }
    ]
  })
}

# CloudTrail
resource "aws_cloudtrail" "main" {
  count = var.enable_cloudtrail ? 1 : 0
  
  name           = "${var.project_name}-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail[0].bucket

  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-cloudtrail"
  })
}

# ===============================
# Security Monitoring Integration
# ===============================

# GuardDuty findings to SNS (monitoring integration only)
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count = var.enable_guardduty && var.enable_sns_alerts ? 1 : 0
  
  name        = "${var.project_name}-guardduty-findings"
  description = "Capture GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  depends_on = [
    aws_sns_topic.alerts,
    aws_sns_topic_policy.alerts,
    aws_guardduty_detector.main
  ]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-guardduty-rule"
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  count = var.enable_guardduty && var.enable_sns_alerts ? 1 : 0
  
  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts[0].arn
} 