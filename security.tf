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