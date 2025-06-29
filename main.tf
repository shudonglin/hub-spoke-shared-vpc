# ===============================
# VPCs
# ===============================

resource "aws_vpc" "vpcs" {
  for_each = local.vpcs

  cidr_block           = each.value.cidr
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support

  tags = merge(local.common_tags, {
    Name = each.value.name
    Type = each.value.type
  })
}

# ===============================
# Internet Gateways
# ===============================

resource "aws_internet_gateway" "igws" {
  for_each = local.vpcs

  vpc_id = aws_vpc.vpcs[each.key].id

  tags = merge(local.common_tags, {
    Name = "${each.value.name}-igw"
  })
}

# ===============================
# Public Subnets
# ===============================

resource "aws_subnet" "public_subnets" {
  for_each = {
    for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
    "${pair[0]}-public-${pair[1]}" => {
      vpc_key = pair[0]
      az_index = pair[1]
    }
  }

  vpc_id                  = aws_vpc.vpcs[each.value.vpc_key].id
  cidr_block              = local.subnet_configs[each.value.vpc_key].public_subnets[each.value.az_index]
  availability_zone       = local.azs[each.value.az_index]
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${local.vpcs[each.value.vpc_key].name}-public-${local.azs[each.value.az_index]}"
    Type = "Public"
  })
}

# ===============================
# Private Subnets
# ===============================

resource "aws_subnet" "private_subnets" {
  for_each = {
    for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
    "${pair[0]}-private-${pair[1]}" => {
      vpc_key = pair[0]
      az_index = pair[1]
    }
  }

  vpc_id            = aws_vpc.vpcs[each.value.vpc_key].id
  cidr_block        = local.subnet_configs[each.value.vpc_key].private_subnets[each.value.az_index]
  availability_zone = local.azs[each.value.az_index]

  tags = merge(local.common_tags, {
    Name = "${local.vpcs[each.value.vpc_key].name}-private-${local.azs[each.value.az_index]}"
    Type = "Private"
  })
}

# ===============================
# Database Subnets
# ===============================

resource "aws_subnet" "database_subnets" {
  for_each = {
    for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
    "${pair[0]}-database-${pair[1]}" => {
      vpc_key = pair[0]
      az_index = pair[1]
    }
  }

  vpc_id            = aws_vpc.vpcs[each.value.vpc_key].id
  cidr_block        = local.subnet_configs[each.value.vpc_key].database_subnets[each.value.az_index]
  availability_zone = local.azs[each.value.az_index]

  tags = merge(local.common_tags, {
    Name = "${local.vpcs[each.value.vpc_key].name}-database-${local.azs[each.value.az_index]}"
    Type = "Database"
  })
}

# ===============================
# Transit Gateway Subnets
# ===============================

resource "aws_subnet" "tgw_subnets" {
  for_each = {
    for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
    "${pair[0]}-tgw-${pair[1]}" => {
      vpc_key = pair[0]
      az_index = pair[1]
    }
  }

  vpc_id            = aws_vpc.vpcs[each.value.vpc_key].id
  cidr_block        = local.subnet_configs[each.value.vpc_key].tgw_subnets[each.value.az_index]
  availability_zone = local.azs[each.value.az_index]

  tags = merge(local.common_tags, {
    Name = "${local.vpcs[each.value.vpc_key].name}-tgw-${local.azs[each.value.az_index]}"
    Type = "TransitGateway"
  })
}

# ===============================
# Elastic IPs for NAT Gateways
# ===============================

resource "aws_eip" "nat_eips" {
  for_each = var.enable_nat_gateway ? (
    var.single_nat_gateway ? 
    { for vpc_key in keys(local.vpcs) : "${vpc_key}-0" => { vpc_key = vpc_key, az_index = 0 } } :
    {
      for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
      "${pair[0]}-${pair[1]}" => {
        vpc_key = pair[0]
        az_index = pair[1]
      }
    }
  ) : {}

  domain = "vpc"

  tags = merge(local.common_tags, {
    Name = "${local.vpcs[each.value.vpc_key].name}-nat-eip-${each.value.az_index}"
  })

  depends_on = [aws_internet_gateway.igws]
}

# ===============================
# NAT Gateways
# ===============================

resource "aws_nat_gateway" "nat_gws" {
  for_each = var.enable_nat_gateway ? (
    var.single_nat_gateway ?
    { for vpc_key in keys(local.vpcs) : "${vpc_key}-0" => { vpc_key = vpc_key, az_index = 0 } } :
    {
      for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
      "${pair[0]}-${pair[1]}" => {
        vpc_key = pair[0]
        az_index = pair[1]
      }
    }
  ) : {}

  allocation_id = aws_eip.nat_eips[each.key].id
  subnet_id     = aws_subnet.public_subnets["${each.value.vpc_key}-public-${each.value.az_index}"].id

  tags = merge(local.common_tags, {
    Name = "${local.vpcs[each.value.vpc_key].name}-nat-gw-${each.value.az_index}"
  })

  depends_on = [aws_internet_gateway.igws]
}

# ===============================
# Transit Gateway
# ===============================

resource "aws_ec2_transit_gateway" "tgw" {
  description                     = "${var.project_name} Transit Gateway"
  amazon_side_asn                 = 64512
  auto_accept_shared_attachments  = "enable"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-tgw"
  })
}

# ===============================
# Transit Gateway VPC Attachments
# ===============================

resource "aws_ec2_transit_gateway_vpc_attachment" "tgw_attachments" {
  for_each = local.vpcs

  subnet_ids         = [for i in range(length(local.azs)) : aws_subnet.tgw_subnets["${each.key}-tgw-${i}"].id]
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id
  vpc_id             = aws_vpc.vpcs[each.key].id

  tags = merge(local.common_tags, {
    Name = "${each.value.name}-tgw-attachment"
  })
}

# ===============================
# Transit Gateway Route Tables
# ===============================

resource "aws_ec2_transit_gateway_route_table" "shared_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-shared-rt"
  })
}

resource "aws_ec2_transit_gateway_route_table" "spoke_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-spoke-rt"
  })
}

# ===============================
# Transit Gateway Route Table Associations
# ===============================

resource "aws_ec2_transit_gateway_route_table_association" "shared_association" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.tgw_attachments["shared"].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.shared_rt.id
}

resource "aws_ec2_transit_gateway_route_table_association" "spoke_associations" {
  for_each = { for k, v in local.vpcs : k => v if v.type == "spoke" }

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.tgw_attachments[each.key].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke_rt.id
}

# ===============================
# Transit Gateway Route Table Propagations
# ===============================

resource "aws_ec2_transit_gateway_route_table_propagation" "shared_propagations" {
  for_each = { for k, v in local.vpcs : k => v if v.type == "spoke" }

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.tgw_attachments[each.key].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.shared_rt.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "spoke_propagations" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.tgw_attachments["shared"].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke_rt.id
}

# NEW: Enable spoke-to-spoke communication (optional)
resource "aws_ec2_transit_gateway_route_table_propagation" "spoke_to_spoke_propagations" {
  for_each = var.enable_spoke_to_spoke_communication ? { for k, v in local.vpcs : k => v if v.type == "spoke" } : {}

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.tgw_attachments[each.key].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke_rt.id
}

# ===============================
# Route Tables - Public
# ===============================

resource "aws_route_table" "public_rts" {
  for_each = local.vpcs

  vpc_id = aws_vpc.vpcs[each.key].id

  tags = merge(local.common_tags, {
    Name = "${each.value.name}-public-rt"
  })
}

resource "aws_route" "public_internet_routes" {
  for_each = local.vpcs

  route_table_id         = aws_route_table.public_rts[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igws[each.key].id
}

# Routes from public subnets to other VPCs via Transit Gateway (needed for ALB health checks)
resource "aws_route" "public_tgw_routes" {
  for_each = {
    for pair in setproduct(keys(local.vpcs), values(local.vpcs)) :
    "${pair[0]}-to-${pair[1].name}" => {
      source_vpc = pair[0]
      dest_cidr = pair[1].cidr
      dest_name = pair[1].name
    }
    if pair[0] != replace(pair[1].name, "${var.project_name}-", "") && replace(pair[1].name, "${var.project_name}-", "") != "${pair[0]}-vpc"
  }

  route_table_id         = aws_route_table.public_rts[each.value.source_vpc].id
  destination_cidr_block = each.value.dest_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.tgw.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.tgw_attachments]
}

resource "aws_route_table_association" "public_rt_associations" {
  for_each = {
    for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
    "${pair[0]}-public-${pair[1]}" => {
      vpc_key = pair[0]
      az_index = pair[1]
    }
  }

  subnet_id      = aws_subnet.public_subnets[each.key].id
  route_table_id = aws_route_table.public_rts[each.value.vpc_key].id
}

# ===============================
# Route Tables - Private
# ===============================

resource "aws_route_table" "private_rts" {
  for_each = var.single_nat_gateway ? local.vpcs : {
    for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
    "${pair[0]}-${pair[1]}" => {
      vpc_key = pair[0]
      vpc_name = local.vpcs[pair[0]].name
      az_index = pair[1]
    }
  }

  vpc_id = var.single_nat_gateway ? aws_vpc.vpcs[each.key].id : aws_vpc.vpcs[each.value.vpc_key].id

  tags = merge(local.common_tags, {
    Name = var.single_nat_gateway ? "${each.value.name}-private-rt" : "${each.value.vpc_name}-private-rt-${each.value.az_index}"
  })
}

resource "aws_route" "private_nat_routes" {
  for_each = var.enable_nat_gateway ? (
    var.single_nat_gateway ? local.vpcs : {
      for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
      "${pair[0]}-${pair[1]}" => {
        vpc_key = pair[0]
        az_index = pair[1]
      }
    }
  ) : {}

  route_table_id         = var.single_nat_gateway ? aws_route_table.private_rts[each.key].id : aws_route_table.private_rts[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.single_nat_gateway ? aws_nat_gateway.nat_gws["${each.key}-0"].id : aws_nat_gateway.nat_gws[each.key].id
}

resource "aws_route" "private_tgw_routes" {
  for_each = {
    for pair in setproduct(keys(local.vpcs), values(local.vpcs)) :
    "${pair[0]}-to-${pair[1].name}" => {
      source_vpc = pair[0]
      dest_cidr = pair[1].cidr
      dest_name = pair[1].name
    }
    if pair[0] != replace(pair[1].name, "${var.project_name}-", "") && replace(pair[1].name, "${var.project_name}-", "") != "${pair[0]}-vpc"
  }

  route_table_id         = var.single_nat_gateway ? aws_route_table.private_rts[each.value.source_vpc].id : aws_route_table.private_rts["${each.value.source_vpc}-0"].id
  destination_cidr_block = each.value.dest_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.tgw.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.tgw_attachments]
}

resource "aws_route_table_association" "private_rt_associations" {
  for_each = {
    for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
    "${pair[0]}-private-${pair[1]}" => {
      vpc_key = pair[0]
      az_index = pair[1]
    }
  }

  subnet_id      = aws_subnet.private_subnets[each.key].id
  route_table_id = var.single_nat_gateway ? aws_route_table.private_rts[each.value.vpc_key].id : aws_route_table.private_rts["${each.value.vpc_key}-${each.value.az_index}"].id
}

# ===============================
# Route Tables - Database
# ===============================

resource "aws_route_table" "database_rts" {
  for_each = local.vpcs

  vpc_id = aws_vpc.vpcs[each.key].id

  tags = merge(local.common_tags, {
    Name = "${each.value.name}-database-rt"
  })
}

resource "aws_route" "database_tgw_routes" {
  for_each = {
    for pair in setproduct(keys(local.vpcs), values(local.vpcs)) :
    "${pair[0]}-to-${pair[1].name}" => {
      source_vpc = pair[0]
      dest_cidr = pair[1].cidr
      dest_name = pair[1].name
    }
    if pair[0] != replace(pair[1].name, "${var.project_name}-", "") && replace(pair[1].name, "${var.project_name}-", "") != "${pair[0]}-vpc"
  }

  route_table_id         = aws_route_table.database_rts[each.value.source_vpc].id
  destination_cidr_block = each.value.dest_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.tgw.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.tgw_attachments]
}

resource "aws_route_table_association" "database_rt_associations" {
  for_each = {
    for pair in setproduct(keys(local.vpcs), range(length(local.azs))) :
    "${pair[0]}-database-${pair[1]}" => {
      vpc_key = pair[0]
      az_index = pair[1]
    }
  }

  subnet_id      = aws_subnet.database_subnets[each.key].id
  route_table_id = aws_route_table.database_rts[each.value.vpc_key].id
}

# ===============================
# Route53 Private Hosted Zone
# ===============================

resource "aws_route53_zone" "private_zone" {
  name = var.domain_name

  vpc {
    vpc_id = aws_vpc.vpcs["shared"].id
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-private-zone"
  })
}

# Associate private hosted zone with spoke VPCs
resource "aws_route53_zone_association" "spoke_zone_associations" {
  for_each = { for k, v in local.vpcs : k => v if v.type == "spoke" }

  zone_id = aws_route53_zone.private_zone.zone_id
  vpc_id  = aws_vpc.vpcs[each.key].id
}

# ===============================
# Route53 Resolver Security Group
# ===============================

resource "aws_security_group" "resolver_sg" {
  name_prefix = "${var.project_name}-resolver-"
  vpc_id      = aws_vpc.vpcs["shared"].id

  ingress {
    description = "DNS TCP"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [for vpc in local.vpcs : vpc.cidr]
  }

  ingress {
    description = "DNS UDP"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [for vpc in local.vpcs : vpc.cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-resolver-sg"
  })
}

# ===============================
# Route53 Resolver Endpoints
# ===============================

resource "aws_route53_resolver_endpoint" "inbound" {
  name      = "${var.project_name}-inbound-resolver"
  direction = "INBOUND"

  security_group_ids = [aws_security_group.resolver_sg.id]

  dynamic "ip_address" {
    for_each = range(length(local.azs))
    content {
      subnet_id = aws_subnet.private_subnets["shared-private-${ip_address.key}"].id
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-inbound-resolver"
  })
}

resource "aws_route53_resolver_endpoint" "outbound" {
  name      = "${var.project_name}-outbound-resolver"
  direction = "OUTBOUND"

  security_group_ids = [aws_security_group.resolver_sg.id]

  dynamic "ip_address" {
    for_each = range(length(local.azs))
    content {
      subnet_id = aws_subnet.private_subnets["shared-private-${ip_address.key}"].id
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-outbound-resolver"
  })
}

# ===============================
# Route53 Resolver Rules
# ===============================

# Note: Since Route53 private hosted zone is associated with spoke VPCs,
# DNS resolution should work automatically via VPC DNS resolver.
# If issues persist, uncomment the resolver rules below.

# # Resolver rule for custom domain (uncomment if needed)
# resource "aws_route53_resolver_rule" "custom_domain" {
#   domain_name          = var.domain_name
#   name                 = "${var.project_name}-custom-domain-rule"
#   rule_type            = "FORWARD"
#   resolver_endpoint_id = aws_route53_resolver_endpoint.outbound.id
#
#   # Forward to inbound resolver endpoint IPs
#   dynamic "target_ip" {
#     for_each = aws_route53_resolver_endpoint.inbound.ip_address
#     content {
#       ip = target_ip.value.ip
#     }
#   }
#
#   tags = merge(local.common_tags, {
#     Name = "${var.project_name}-custom-domain-rule"
#   })
# }
#
# # Associate resolver rule with spoke VPCs
# resource "aws_route53_resolver_rule_association" "spoke_vpc_associations" {
#   for_each = { for k, v in local.vpcs : k => v if v.type == "spoke" }
#
#   resolver_rule_id = aws_route53_resolver_rule.custom_domain.id
#   vpc_id           = aws_vpc.vpcs[each.key].id
# }

# ===============================
# VPC Endpoints in Shared VPC
# ===============================

# Gateway endpoints (S3 and DynamoDB)
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.vpcs["shared"].id
  service_name = "com.amazonaws.${var.aws_region}.s3"
  
  route_table_ids = concat(
    # Private route tables for shared VPC
    var.single_nat_gateway ? [aws_route_table.private_rts["shared"].id] : [
      for i in range(length(local.azs)) : aws_route_table.private_rts["shared-${i}"].id
    ],
    # Database route table for shared VPC
    [aws_route_table.database_rts["shared"].id]
  )

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-s3-endpoint"
  })
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id       = aws_vpc.vpcs["shared"].id
  service_name = "com.amazonaws.${var.aws_region}.dynamodb"
  
  route_table_ids = concat(
    # Private route tables for shared VPC
    var.single_nat_gateway ? [aws_route_table.private_rts["shared"].id] : [
      for i in range(length(local.azs)) : aws_route_table.private_rts["shared-${i}"].id
    ],
    # Database route table for shared VPC
    [aws_route_table.database_rts["shared"].id]
  )

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-dynamodb-endpoint"
  })
}

# ===============================
# VPC Flow Logs and KMS
# ===============================

# KMS key for encrypting VPC Flow Logs
resource "aws_kms_key" "vpc_flow_logs_key" {
  count       = var.enable_vpc_flow_logs ? 1 : 0
  description = "KMS key for VPC Flow Logs encryption"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-vpc-flow-logs-key"
  })
}

# KMS key alias
resource "aws_kms_alias" "vpc_flow_logs_key_alias" {
  count         = var.enable_vpc_flow_logs ? 1 : 0
  name          = "alias/${var.project_name}-vpc-flow-logs"
  target_key_id = aws_kms_key.vpc_flow_logs_key[0].key_id
}

# CloudWatch Log Groups for VPC Flow Logs
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  for_each = var.enable_vpc_flow_logs ? local.vpcs : {}

  name              = "/aws/vpc/flowlogs/${each.key}"
  retention_in_days = var.flow_logs_retention_days
  kms_key_id        = aws_kms_key.vpc_flow_logs_key[0].arn

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.key}-flow-logs"
  })
}

# IAM role for VPC Flow Logs
resource "aws_iam_role" "vpc_flow_logs_role" {
  count = var.enable_vpc_flow_logs ? 1 : 0
  name  = "${var.project_name}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# IAM policy for VPC Flow Logs
resource "aws_iam_role_policy" "vpc_flow_logs_policy" {
  count = var.enable_vpc_flow_logs ? 1 : 0
  name  = "${var.project_name}-vpc-flow-logs-policy"
  role  = aws_iam_role.vpc_flow_logs_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}

# VPC Flow Logs
resource "aws_flow_log" "vpc_flow_logs" {
  for_each = var.enable_vpc_flow_logs ? local.vpcs : {}

  iam_role_arn    = aws_iam_role.vpc_flow_logs_role[0].arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs[each.key].arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.vpcs[each.key].id

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.key}-flow-log"
  })
}

# ===============================
# Test EC2 Instances
# ===============================

# Get the latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  count       = var.create_test_instances ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Security groups for test instances (one per VPC)
resource "aws_security_group" "test_instance_sg" {
  for_each = var.create_test_instances ? toset(var.test_instance_vpcs) : toset([])

  name_prefix = "${var.project_name}-test-${each.key}-"
  vpc_id      = aws_vpc.vpcs[each.key].id

  # Allow SSH from all VPC CIDRs
  ingress {
    description = "SSH from VPCs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [for vpc in local.vpcs : vpc.cidr]
  }

  # Allow ICMP for ping testing between all VPCs
  ingress {
    description = "ICMP (ping) from all VPCs"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [for vpc in local.vpcs : vpc.cidr]
  }

  # Allow HTTP for testing web connectivity
  ingress {
    description = "HTTP from all VPCs"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [for vpc in local.vpcs : vpc.cidr]
  }

  # Allow HTTPS for testing web connectivity
  ingress {
    description = "HTTPS from all VPCs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [for vpc in local.vpcs : vpc.cidr]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-test-${each.key}-sg"
  })
}

# IAM role for test instances (allows SSM access)
resource "aws_iam_role" "test_instance_role" {
  count = var.create_test_instances ? 1 : 0
  name  = "${var.project_name}-test-instances-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Attach SSM managed policy to the role
resource "aws_iam_role_policy_attachment" "test_instance_ssm_policy" {
  count      = var.create_test_instances ? 1 : 0
  role       = aws_iam_role.test_instance_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Instance profile for test instances
resource "aws_iam_instance_profile" "test_instance_profile" {
  count = var.create_test_instances ? 1 : 0
  name  = "${var.project_name}-test-instances-profile"
  role  = aws_iam_role.test_instance_role[0].name

  tags = local.common_tags
}

# Test EC2 instances
resource "aws_instance" "test_instances" {
  for_each = var.create_test_instances ? toset(var.test_instance_vpcs) : toset([])

  ami                    = data.aws_ami.amazon_linux[0].id
  instance_type          = var.test_instance_type
  subnet_id              = aws_subnet.private_subnets["${each.key}-private-0"].id
  vpc_security_group_ids = [aws_security_group.test_instance_sg[each.key].id]
  iam_instance_profile   = aws_iam_instance_profile.test_instance_profile[0].name

  user_data_base64 = base64encode(<<-EOF
              #!/bin/bash
              yum update -y
              yum install -y awscli htop curl wget telnet nmap-ncat bind-utils
              
              # Install CloudWatch agent
              wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
              rpm -U ./amazon-cloudwatch-agent.rpm
              
              # Configure web server based on VPC
              if [ "${each.key}" = "spoke1" ]; then
                # Install and configure nginx web server for WAF testing
                amazon-linux-extras install -y nginx1
              
              # Create main website
              cat > /usr/share/nginx/html/index.html << 'HTML'
              <!DOCTYPE html>
              <html lang="en">
              <head>
                  <meta charset="UTF-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                  <title>Hub-Spoke Web Application</title>
                  <style>
                      body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }
                      .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                      .header { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
                      .info { background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 15px 0; }
                      .section { margin: 20px 0; }
                      .warning { color: #d9534f; }
                      .success { color: #5cb85c; }
                      .form-container { background: #f9f9f9; padding: 20px; border-radius: 5px; margin: 20px 0; }
                      input, textarea { width: 100%; padding: 8px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; }
                      button { background: #007acc; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
                      button:hover { background: #005999; }
                  </style>
              </head>
              <body>
                  <div class="container">
                      <h1 class="header">🛡️ Hub-Spoke Web Application with WAF Protection</h1>
                      
                      <div class="info">
                          <h3>Instance Information</h3>
                          <p><strong>Instance ID:</strong> <span id="instance-id">Loading...</span></p>
                          <p><strong>Private IP:</strong> <span id="private-ip">Loading...</span></p>
                          <p><strong>Availability Zone:</strong> <span id="az">Loading...</span></p>
                          <p><strong>VPC:</strong> ${each.key}</p>
                          <p><strong>Current Time:</strong> <span id="current-time"></span></p>
                      </div>

                      <div class="section">
                          <h3>🧪 WAF Testing Endpoints</h3>
                          <p>Test various WAF rules with these links:</p>
                          <ul>
                              <li><a href="/admin">Admin Panel (should be blocked)</a></li>
                              <li><a href="/api/users">API Endpoint</a></li>
                              <li><a href="/test-sql">SQL Injection Test</a></li>
                              <li><a href="/test-xss">XSS Test</a></li>
                              <li><a href="/health">Health Check</a></li>
                          </ul>
                      </div>

                      <div class="form-container">
                          <h3>🔍 Security Test Form</h3>
                          <p class="warning">⚠️ The forms below are for testing WAF rules - they should be blocked by WAF!</p>
                          <form method="POST" action="/test-form">
                              <label>Username:</label>
                              <input type="text" name="username" placeholder="Try: admin' OR '1'='1">
                              
                              <label>Message:</label>
                              <textarea name="message" placeholder="Try: <script>alert('XSS')</script>"></textarea>
                              
                              <button type="submit">Submit (Should be blocked by WAF)</button>
                          </form>
                      </div>

                      <div class="section">
                          <h3>📊 Network Architecture</h3>
                          <p>This application demonstrates a hub-spoke architecture with:</p>
                          <ul>
                              <li class="success">✅ AWS WAF protection against OWASP Top 10</li>
                              <li class="success">✅ Rate limiting and geo-blocking</li>
                              <li class="success">✅ Cross-VPC communication via Transit Gateway</li>
                              <li class="success">✅ Centralized security in shared VPC</li>
                          </ul>
                      </div>
                  </div>

                  <script>
                      // Load instance metadata
                      fetch('http://169.254.169.254/latest/meta-data/instance-id')
                          .then(r => r.text()).then(d => document.getElementById('instance-id').textContent = d)
                          .catch(() => document.getElementById('instance-id').textContent = 'Unable to load');
                      
                      fetch('http://169.254.169.254/latest/meta-data/local-ipv4')
                          .then(r => r.text()).then(d => document.getElementById('private-ip').textContent = d)
                          .catch(() => document.getElementById('private-ip').textContent = 'Unable to load');
                      
                      fetch('http://169.254.169.254/latest/meta-data/placement/availability-zone')
                          .then(r => r.text()).then(d => document.getElementById('az').textContent = d)
                          .catch(() => document.getElementById('az').textContent = 'Unable to load');
                      
                      // Update time
                      setInterval(() => {
                          document.getElementById('current-time').textContent = new Date().toLocaleString();
                      }, 1000);
                  </script>
              </body>
              </html>
HTML

              # Create test endpoints for WAF testing
              mkdir -p /usr/share/nginx/html/admin
              mkdir -p /usr/share/nginx/html/api
              
              # Admin panel (should be blocked by WAF)
              cat > /usr/share/nginx/html/admin/index.html << 'HTML'
              <h1>Admin Panel</h1>
              <p>⚠️ This should be blocked by AWS WAF Admin Protection rules!</p>
              <p>If you can see this, WAF rules may need adjustment.</p>
HTML

              # API endpoint
              cat > /usr/share/nginx/html/api/users/index.html << 'HTML'
              <h1>User API</h1>
              <p>This is a sample API endpoint.</p>
              <p>Status: Active</p>
HTML

              # Health check endpoint
              cat > /usr/share/nginx/html/health/index.html << 'HTML'
              {"status":"healthy","service":"hub-spoke-web","timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
HTML

              # Configure nginx
              systemctl start nginx
              systemctl enable nginx
              
              # Create custom nginx config for WAF testing
              cat > /etc/nginx/conf.d/waf-test.conf << 'NGINX'
              server {
                  listen 80 default_server;
                  server_name _;
                  root /usr/share/nginx/html;
                  index index.html;
                  
                  # Enable detailed logging for WAF analysis
                  access_log /var/log/nginx/access.log combined;
                  error_log /var/log/nginx/error.log warn;
                  
                  # Health check endpoint
                  location /health {
                      add_header Content-Type application/json;
                      return 200 '{"status":"healthy","service":"hub-spoke-web","vpc":"${each.key}","timestamp":"$time_iso8601"}';
                  }
                  
                  # SQL injection test endpoint
                  location /test-sql {
                      return 200 '<h1>SQL Injection Test</h1><p>Try: /test-sql?id=1\' OR \'1\'=\'1</p>';
                  }
                  
                  # XSS test endpoint  
                  location /test-xss {
                      return 200 '<h1>XSS Test</h1><p>Try posting: &lt;script&gt;alert(\"XSS\")&lt;/script&gt;</p>';
                  }
                  
                  # Form submission endpoint (should be blocked by WAF)
                  location /test-form {
                      if ($request_method = POST) {
                          return 200 '<h1>Form Submitted</h1><p>⚠️ This should have been blocked by WAF!</p>';
                      }
                      return 405;
                  }
                  
                  # Default location
                  location / {
                      try_files $uri $uri/ =404;
                  }
              }
NGINX

              # Restart nginx to apply config
              systemctl restart nginx
              
              else
                # Install simple web server for spoke2 (connectivity testing)
                yum install -y httpd
                
                # Create simple test page
                cat > /var/www/html/index.html << 'HTML'
              <!DOCTYPE html>
              <html>
              <head>
                  <title>Test Instance - ${each.key}</title>
                  <style>
                      body { font-family: Arial; margin: 40px; background: #f0f8ff; }
                      .container { background: white; padding: 30px; border-radius: 8px; }
                      .header { color: #2c5282; border-bottom: 2px solid #3182ce; padding-bottom: 10px; }
                  </style>
              </head>
              <body>
                  <div class="container">
                      <h1 class="header">🔗 Test Instance - ${each.key} VPC</h1>
                      <p><strong>Instance ID:</strong> <span id="instance-id">Loading...</span></p>
                      <p><strong>Private IP:</strong> <span id="private-ip">Loading...</span></p>
                      <p><strong>VPC:</strong> ${each.key}</p>
                      <p><strong>Purpose:</strong> Connectivity Testing</p>
                      
                      <h3>Status</h3>
                      <p>✅ This instance is reachable from the ALB in shared VPC via Transit Gateway</p>
                      
                      <h3>Test Endpoints</h3>
                      <ul>
                          <li><a href="/health">Health Check</a></li>
                          <li><a href="/info">System Info</a></li>
                      </ul>
                  </div>
                  
                  <script>
                      fetch('http://169.254.169.254/latest/meta-data/instance-id')
                          .then(r => r.text()).then(d => document.getElementById('instance-id').textContent = d);
                      fetch('http://169.254.169.254/latest/meta-data/local-ipv4')
                          .then(r => r.text()).then(d => document.getElementById('private-ip').textContent = d);
                  </script>
              </body>
              </html>
HTML

                # Create health check endpoint
                mkdir -p /var/www/html/health
                echo '{"status":"healthy","service":"test-instance","vpc":"${each.key}"}' > /var/www/html/health/index.html
                
                # Create system info endpoint
                mkdir -p /var/www/html/info
                cat > /var/www/html/info/index.html << 'HTML'
              <h1>System Information</h1>
              <p>Hostname: $(hostname)</p>
              <p>Uptime: $(uptime)</p>
              <p>Date: $(date)</p>
HTML

                # Start Apache
                systemctl start httpd
                systemctl enable httpd
              fi
              
              # Create connectivity test script
              cat > /home/ec2-user/test-connectivity.sh << 'SCRIPT'
              #!/bin/bash
              echo "=== Connectivity Test from ${each.key} VPC ==="
              echo "Current instance IP: $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)"
              echo ""
              
              # Test DNS resolution
              echo "=== DNS Resolution Test ==="
              for vpc in shared spoke1 spoke2; do
                if [ "$vpc" != "${each.key}" ]; then
                  echo "Testing DNS for test-$vpc.${var.domain_name}..."
                  nslookup test-$vpc.${var.domain_name} || echo "DNS lookup failed for test-$vpc"
                fi
              done
              echo ""
              
              # Test ping connectivity
              echo "=== Ping Test ==="
              for vpc in shared spoke1 spoke2; do
                if [ "$vpc" != "${each.key}" ]; then
                  echo "Pinging test-$vpc.${var.domain_name}..."
                  ping -c 3 test-$vpc.${var.domain_name} || echo "Ping failed to test-$vpc"
                  echo ""
                fi
              done
              
              # Test HTTP connectivity
              echo "=== HTTP Test ==="
              for vpc in shared spoke1 spoke2; do
                if [ "$vpc" != "${each.key}" ]; then
                  echo "Testing HTTP to test-$vpc.${var.domain_name}..."
                  curl -s --connect-timeout 5 http://test-$vpc.${var.domain_name} || echo "HTTP connection failed to test-$vpc"
                  echo ""
                fi
              done
              SCRIPT
              
              chmod +x /home/ec2-user/test-connectivity.sh
              chown ec2-user:ec2-user /home/ec2-user/test-connectivity.sh
              EOF
  )

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-test-${each.key}"
  })
}

# Route53 records for test instances
resource "aws_route53_record" "test_instance_records" {
  for_each = var.create_test_instances ? toset(var.test_instance_vpcs) : toset([])

  zone_id = aws_route53_zone.private_zone.zone_id
  name    = "test-${each.key}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.test_instances[each.key].private_ip]
}

# ===============================
# Optional Bastion Host
# ===============================

# EIP for bastion host
resource "aws_eip" "bastion_eip" {
  count  = var.create_bastion_host ? 1 : 0
  domain = "vpc"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bastion-eip"
  })
}

# Security group for bastion host
resource "aws_security_group" "bastion_sg" {
  count       = var.create_bastion_host ? 1 : 0
  name_prefix = "${var.project_name}-bastion-"
  vpc_id      = aws_vpc.vpcs["shared"].id

  # Allow SSH from specified CIDR blocks
  ingress {
    description = "SSH from allowed IPs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_allowed_cidr_blocks
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bastion-sg"
  })
}

# Security group rule to allow SSH from bastion to test instances
resource "aws_security_group_rule" "test_instances_ssh_from_bastion" {
  for_each = var.create_bastion_host && var.create_test_instances ? aws_security_group.test_instance_sg : {}

  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion_sg[0].id
  security_group_id        = each.value.id
}

# AMI for bastion host
data "aws_ami" "bastion_amazon_linux" {
  count       = var.create_bastion_host ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Bastion host EC2 instance
resource "aws_instance" "bastion" {
  count                       = var.create_bastion_host ? 1 : 0
  ami                         = data.aws_ami.bastion_amazon_linux[0].id
  instance_type               = var.bastion_instance_type
  subnet_id                   = aws_subnet.public_subnets["shared-public-0"].id
  vpc_security_group_ids      = [aws_security_group.bastion_sg[0].id]
  iam_instance_profile        = var.create_test_instances ? aws_iam_instance_profile.test_instance_profile[0].name : null
  associate_public_ip_address = true

  user_data_base64 = base64encode(<<-EOF
              #!/bin/bash
              yum update -y
              yum install -y awscli htop curl wget telnet nmap-ncat bind-utils

              # Create helper script for connecting to test instances
              cat > /home/ec2-user/connect-to-instance.sh << 'SCRIPT'
              #!/bin/bash
              echo "=== Bastion Host - Instance Connection Helper ==="
              echo "Available test instances:"
              echo "- test-spoke1.${var.domain_name}"
              echo "- test-spoke2.${var.domain_name}"
              echo ""
              echo "Usage examples:"
              echo "ssh ec2-user@test-spoke1.${var.domain_name}"
              echo "ssh ec2-user@test-spoke2.${var.domain_name}"
              echo ""
              echo "Or use SSM Session Manager (no SSH needed):"
              echo "aws ssm start-session --target <INSTANCE_ID>"
              SCRIPT

              chmod +x /home/ec2-user/connect-to-instance.sh
              chown ec2-user:ec2-user /home/ec2-user/connect-to-instance.sh
              EOF
  )

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bastion-host"
  })
}

# Associate EIP with bastion host
resource "aws_eip_association" "bastion_eip_assoc" {
  count       = var.create_bastion_host ? 1 : 0
  instance_id = aws_instance.bastion[0].id
  allocation_id = aws_eip.bastion_eip[0].id
}

# Route53 record for bastion host
resource "aws_route53_record" "bastion_record" {
  count   = var.create_bastion_host ? 1 : 0
  zone_id = aws_route53_zone.private_zone.zone_id
  name    = "bastion"
  type    = "A"
  ttl     = 300
  records = [aws_instance.bastion[0].private_ip]
} 