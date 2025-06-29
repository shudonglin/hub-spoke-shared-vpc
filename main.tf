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

# Note: Route53 private hosted zone is associated with spoke VPCs for automatic DNS resolution.
# Resolver rules below provide additional DNS forwarding capabilities for cross-VPC resolution.

# Resolver rule for custom domain - forwards DNS queries to inbound resolver
resource "aws_route53_resolver_rule" "custom_domain" {
  domain_name          = var.domain_name
  name                 = "${var.project_name}-custom-domain-rule"
  rule_type            = "FORWARD"
  resolver_endpoint_id = aws_route53_resolver_endpoint.outbound.id

  # Forward to inbound resolver endpoint IPs
  dynamic "target_ip" {
    for_each = aws_route53_resolver_endpoint.inbound.ip_address
    content {
      ip = target_ip.value.ip
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-custom-domain-rule"
  })
}

# Associate resolver rule with spoke VPCs for cross-VPC DNS resolution
resource "aws_route53_resolver_rule_association" "spoke_vpc_associations" {
  for_each = { for k, v in local.vpcs : k => v if v.type == "spoke" }

  resolver_rule_id = aws_route53_resolver_rule.custom_domain.id
  vpc_id           = aws_vpc.vpcs[each.key].id
}

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

  # ICMP (ping) disabled for security - use TCP connectivity tests instead

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

# Attach CloudWatch agent policy to the role
resource "aws_iam_role_policy_attachment" "test_instance_cloudwatch_policy" {
  count      = var.create_test_instances ? 1 : 0
  role       = aws_iam_role.test_instance_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
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

  user_data_base64 = base64encode(templatefile("${path.module}/scripts/${each.key}-init.sh", {
    DOMAIN_NAME = var.domain_name
  }))

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

 