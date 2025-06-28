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
# VPC Endpoints in Shared VPC
# ===============================

resource "aws_security_group" "vpc_endpoints_sg" {
  name_prefix = "${var.project_name}-vpc-endpoints-"
  vpc_id      = aws_vpc.vpcs["shared"].id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [for vpc in local.vpcs : vpc.cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-vpc-endpoints-sg"
  })
}

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

# Interface endpoints
resource "aws_vpc_endpoint" "interface_endpoints" {
  for_each = {
    ssm         = "com.amazonaws.${var.aws_region}.ssm"
    ssmmessages = "com.amazonaws.${var.aws_region}.ssmmessages"
    ec2messages = "com.amazonaws.${var.aws_region}.ec2messages"
  }

  vpc_id              = aws_vpc.vpcs["shared"].id
  service_name        = each.value
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for i in range(length(local.azs)) : aws_subnet.private_subnets["shared-private-${i}"].id]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${each.key}-endpoint"
  })
}

# ===============================
# Test EC2 Instance
# ===============================

# Get the latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  count       = var.create_test_instance ? 1 : 0
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

# Security group for test instance
resource "aws_security_group" "test_instance_sg" {
  count       = var.create_test_instance ? 1 : 0
  name_prefix = "${var.project_name}-test-instance-"
  vpc_id      = aws_vpc.vpcs[var.test_instance_vpc].id

  # Allow SSH from VPC CIDR
  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [for vpc in local.vpcs : vpc.cidr]
  }

  # Allow ICMP for ping testing
  ingress {
    description = "ICMP"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [for vpc in local.vpcs : vpc.cidr]
  }

  # Allow HTTP for testing web connectivity
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [for vpc in local.vpcs : vpc.cidr]
  }

  # Allow HTTPS for testing web connectivity
  ingress {
    description = "HTTPS"
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
    Name = "${var.project_name}-test-instance-sg"
  })
}

# IAM role for test instance (allows SSM access)
resource "aws_iam_role" "test_instance_role" {
  count = var.create_test_instance ? 1 : 0
  name  = "${var.project_name}-test-instance-role"

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
  count      = var.create_test_instance ? 1 : 0
  role       = aws_iam_role.test_instance_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Instance profile for the test instance
resource "aws_iam_instance_profile" "test_instance_profile" {
  count = var.create_test_instance ? 1 : 0
  name  = "${var.project_name}-test-instance-profile"
  role  = aws_iam_role.test_instance_role[0].name

  tags = local.common_tags
}

# Test EC2 instance
resource "aws_instance" "test_instance" {
  count                  = var.create_test_instance ? 1 : 0
  ami                    = data.aws_ami.amazon_linux[0].id
  instance_type          = var.test_instance_type
  subnet_id              = aws_subnet.private_subnets["${var.test_instance_vpc}-private-0"].id
  vpc_security_group_ids = [aws_security_group.test_instance_sg[0].id]
  iam_instance_profile   = aws_iam_instance_profile.test_instance_profile[0].name

  user_data_base64 = base64encode(<<-EOF
              #!/bin/bash
              yum update -y
              yum install -y awscli htop curl wget telnet nmap-ncat bind-utils
              
              # Install CloudWatch agent
              wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
              rpm -U ./amazon-cloudwatch-agent.rpm
              
              # Create a simple web server for testing
              echo "<h1>Test Instance in ${var.test_instance_vpc} VPC</h1>" > /var/www/html/index.html
              echo "<p>Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id)</p>" >> /var/www/html/index.html
              echo "<p>Private IP: $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)</p>" >> /var/www/html/index.html
              echo "<p>AZ: $(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)</p>" >> /var/www/html/index.html
              
              # Install and start httpd
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              EOF
  )

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-test-instance-${var.test_instance_vpc}"
  })
}

# Route53 record for test instance
resource "aws_route53_record" "test_instance_record" {
  count   = var.create_test_instance ? 1 : 0
  zone_id = aws_route53_zone.private_zone.zone_id
  name    = "test-${var.test_instance_vpc}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.test_instance[0].private_ip]
} 