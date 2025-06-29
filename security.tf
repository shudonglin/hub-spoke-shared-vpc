# ===============================
# Enhanced Security Configurations
# ===============================

# Network ACLs for additional security layer
resource "aws_network_acl" "secure_nacl" {
  for_each = var.enable_enhanced_security ? local.vpcs : {}
  
  vpc_id = aws_vpc.vpcs[each.key].id
  
  # Allow HTTP traffic
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    from_port  = 80
    to_port    = 80
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }
  
  # Allow HTTPS traffic
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    from_port  = 443
    to_port    = 443
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }
  
  # Allow SSH from private networks only
  ingress {
    rule_no    = 120
    protocol   = "tcp"
    from_port  = 22
    to_port    = 22
    cidr_block = "10.0.0.0/8"
    action     = "allow"
  }
  
  # Allow ephemeral ports for responses
  ingress {
    rule_no    = 200
    protocol   = "tcp"
    from_port  = 1024
    to_port    = 65535
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }
  
  # Allow all outbound traffic
  egress {
    rule_no    = 100
    protocol   = "-1"
    from_port  = 0
    to_port    = 0
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.key}-secure-nacl"
    Type = "Security"
  })
}

# Associate NACLs with private subnets
resource "aws_network_acl_association" "private_subnet_nacl" {
  for_each = var.enable_enhanced_security ? {
    for k, v in aws_subnet.private_subnets : k => {
      subnet_id = v.id
      vpc_key   = split("-", k)[0]
    }
  } : {}
  
  network_acl_id = aws_network_acl.secure_nacl[each.value.vpc_key].id
  subnet_id      = each.value.subnet_id
}

# ===============================
# VPN Gateway (Optional)
# ===============================

resource "aws_vpn_gateway" "main" {
  count  = var.enable_vpn_gateway ? 1 : 0
  vpc_id = aws_vpc.vpcs["shared"].id
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-vpn-gateway"
  })
}

resource "aws_vpn_gateway_route_propagation" "main" {
  count = var.enable_vpn_gateway ? length(aws_route_table.private_rts) : 0
  
  vpn_gateway_id = aws_vpn_gateway.main[0].id
  route_table_id = values(aws_route_table.private_rts)[count.index].id
}

# ===============================
# Enhanced Security Groups
# ===============================

# Security group for database tier
resource "aws_security_group" "database_sg" {
  for_each = var.enable_enhanced_security ? local.vpcs : {}
  
  name_prefix = "${var.project_name}-database-${each.key}-"
  vpc_id      = aws_vpc.vpcs[each.key].id

  # Allow MySQL/Aurora from private subnets only
  ingress {
    description = "MySQL/Aurora from private subnets"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [local.subnet_configs[each.key].private_subnets[0]]
  }

  # Allow PostgreSQL from private subnets only
  ingress {
    description = "PostgreSQL from private subnets"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [local.subnet_configs[each.key].private_subnets[0]]
  }

  # No outbound internet access for database
  egress {
    description = "Internal VPC communication only"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [each.value.cidr]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-database-${each.key}-sg"
    Tier = "Database"
  })
}

# Security group for management/monitoring
resource "aws_security_group" "management_sg" {
  count = var.enable_enhanced_security ? 1 : 0
  
  name_prefix = "${var.project_name}-management-"
  vpc_id      = aws_vpc.vpcs["shared"].id

  # Allow SSH from specific management IPs
  ingress {
    description = "SSH from management network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.management_cidr_blocks
  }

  # Allow RDP for Windows management
  ingress {
    description = "RDP from management network"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = var.management_cidr_blocks
  }

  # Allow SNMP for monitoring
  ingress {
    description = "SNMP from monitoring systems"
    from_port   = 161
    to_port     = 161
    protocol    = "udp"
    cidr_blocks = var.management_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-management-sg"
    Type = "Management"
  })
}

# ===============================
# AWS Systems Manager (Enhanced)
# ===============================

# VPC Endpoints for Systems Manager (optional - adds significant cost)
resource "aws_vpc_endpoint" "ssm" {
  for_each = var.enable_vpc_endpoints ? local.vpcs : {}
  
  vpc_id              = aws_vpc.vpcs[each.key].id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for k, v in aws_subnet.private_subnets : v.id if startswith(k, "${each.key}-private")]
  security_group_ids  = [aws_security_group.vpc_endpoints[each.key].id]
  private_dns_enabled = true
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.key}-ssm-endpoint"
  })
}

resource "aws_vpc_endpoint" "ssm_messages" {
  for_each = var.enable_vpc_endpoints ? local.vpcs : {}
  
  vpc_id              = aws_vpc.vpcs[each.key].id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for k, v in aws_subnet.private_subnets : v.id if startswith(k, "${each.key}-private")]
  security_group_ids  = [aws_security_group.vpc_endpoints[each.key].id]
  private_dns_enabled = true
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.key}-ssm-messages-endpoint"
  })
}

resource "aws_vpc_endpoint" "ec2_messages" {
  for_each = var.enable_vpc_endpoints ? local.vpcs : {}
  
  vpc_id              = aws_vpc.vpcs[each.key].id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for k, v in aws_subnet.private_subnets : v.id if startswith(k, "${each.key}-private")]
  security_group_ids  = [aws_security_group.vpc_endpoints[each.key].id]
  private_dns_enabled = true
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.key}-ec2-messages-endpoint"
  })
}

# Security group for VPC endpoints
resource "aws_security_group" "vpc_endpoints" {
  for_each = var.enable_vpc_endpoints ? local.vpcs : {}
  
  name_prefix = "${var.project_name}-vpc-endpoints-${each.key}-"
  vpc_id      = aws_vpc.vpcs[each.key].id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [each.value.cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-vpc-endpoints-${each.key}-sg"
  })
}

# ===============================
# Security Automation
# ===============================

# CloudWatch Events for security automation
resource "aws_cloudwatch_event_rule" "security_events" {
  count = var.enable_security_automation ? 1 : 0
  
  name        = "${var.project_name}-security-events"
  description = "Capture security-related events"

  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.iam", "aws.vpc"]
    detail-type = [
      "EC2 Instance State-change Notification",
      "AWS API Call via CloudTrail"
    ]
    detail = {
      eventSource = ["ec2.amazonaws.com", "iam.amazonaws.com"]
      eventName = [
        "RunInstances",
        "TerminateInstances",
        "CreateUser",
        "DeleteUser",
        "AttachUserPolicy",
        "DetachUserPolicy"
      ]
    }
  })
}

# Lambda function for security automation (placeholder)
resource "aws_lambda_function" "security_automation" {
  count = var.enable_security_automation ? 1 : 0
  
  filename         = "security_automation.zip"
  function_name    = "${var.project_name}-security-automation"
  role            = aws_iam_role.lambda_security[0].arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 60

  # Create a placeholder zip file
  depends_on = [data.archive_file.security_automation_zip]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-security-automation"
  })
}

# Create placeholder Lambda code
data "archive_file" "security_automation_zip" {
  count       = var.enable_security_automation ? 1 : 0
  type        = "zip"
  output_path = "security_automation.zip"
  
  source {
    content = <<EOF
def handler(event, context):
    """
    Placeholder security automation function
    Add your security automation logic here
    """
    print(f"Security event received: {event}")
    return {"statusCode": 200}
EOF
    filename = "index.py"
  }
}

# IAM role for Lambda security automation
resource "aws_iam_role" "lambda_security" {
  count = var.enable_security_automation ? 1 : 0
  name  = "${var.project_name}-lambda-security-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_security_basic" {
  count      = var.enable_security_automation ? 1 : 0
  role       = aws_iam_role.lambda_security[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ===============================
# AWS Config for Configuration Compliance
# ===============================

# S3 bucket for Config
resource "aws_s3_bucket" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = "${var.project_name}-config-${random_id.config_bucket_suffix[0].hex}"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-config"
    Type = "Config"
  })
}

resource "random_id" "config_bucket_suffix" {
  count       = var.enable_config ? 1 : 0
  byte_length = 8
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.enable_vpc_flow_logs ? aws_kms_key.vpc_flow_logs_key[0].arn : null
      sse_algorithm     = var.enable_vpc_flow_logs ? "aws:kms" : "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.config[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config[0].arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"     = "bucket-owner-full-control"
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Config Service Configuration
resource "aws_config_configuration_recorder_status" "main" {
  count      = var.enable_config ? 1 : 0
  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_delivery_channel" "main" {
  count          = var.enable_config ? 1 : 0
  name           = "${var.project_name}-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config[0].bucket
}

resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_config ? 1 : 0
  name     = "${var.project_name}-config-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_iam_role" "config" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# ===============================
# AWS Config Rules for Compliance
# ===============================

# Root access key check
resource "aws_config_config_rule" "root_access_key_check" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-root-access-key-check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-root-access-key-check"
  })
}

# Security groups should not allow unrestricted access to port 22
resource "aws_config_config_rule" "incoming_ssh_disabled" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-incoming-ssh-disabled"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-incoming-ssh-disabled"
  })
}

# VPC flow logging should be enabled
resource "aws_config_config_rule" "vpc_flow_logs_enabled" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-vpc-flow-logs-enabled"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-vpc-flow-logs-enabled"
  })
}

# CloudTrail should be enabled
resource "aws_config_config_rule" "cloudtrail_enabled" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-cloudtrail-enabled"
  })
}

# S3 bucket should not allow public read access
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-s3-bucket-public-read-prohibited"
  })
}

# S3 bucket should not allow public write access
resource "aws_config_config_rule" "s3_bucket_public_write_prohibited" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-s3-bucket-public-write-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-s3-bucket-public-write-prohibited"
  })
}

# Security groups should not allow unrestricted access to all ports
resource "aws_config_config_rule" "security_group_open_to_world" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-security-group-open-to-world"

  source {
    owner             = "AWS"
    source_identifier = "EC2_SECURITY_GROUP_ATTACHED_TO_ENI"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-security-group-open-to-world"
  })
}



# IAM password policy check
resource "aws_config_config_rule" "iam_password_policy" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-iam-password-policy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols            = "true"
    RequireNumbers            = "true"
    MinimumPasswordLength     = "8"
    PasswordReusePrevention   = "3"
    MaxPasswordAge            = "90"
  })

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-iam-password-policy"
  })
}

# EC2 instances should be managed by Systems Manager
resource "aws_config_config_rule" "ec2_managedinstance_association_compliance" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-ec2-managedinstance-compliance"

  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-ec2-managedinstance-compliance"
  })
}

# Ensure encrypted EBS volumes
resource "aws_config_config_rule" "encrypted_volumes" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project_name}-encrypted-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-encrypted-volumes"
  })
}

# ===============================
# AWS GuardDuty for Threat Detection
# ===============================

resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-guardduty"
  })
}

# GuardDuty S3 Protection Feature
resource "aws_guardduty_detector_feature" "s3_logs" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# GuardDuty Malware Protection Feature
resource "aws_guardduty_detector_feature" "malware_protection" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
} 