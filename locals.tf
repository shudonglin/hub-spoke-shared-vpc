# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# Local values
locals {
  # Use provided AZs or get the first 3 available AZs
  azs = length(var.availability_zones) > 0 ? var.availability_zones : slice(data.aws_availability_zones.available.names, 0, 3)
  
  # Common tags
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  })

  # VPC configurations
  vpcs = {
    shared = {
      name       = "${var.project_name}-shared-vpc"
      cidr       = var.shared_vpc_cidr
      type       = "shared"
    }
    spoke1 = {
      name       = "${var.project_name}-spoke1-vpc"
      cidr       = var.spoke_vpc_cidrs.spoke1
      type       = "spoke"
    }
    spoke2 = {
      name       = "${var.project_name}-spoke2-vpc"  
      cidr       = var.spoke_vpc_cidrs.spoke2
      type       = "spoke"
    }
  }

  # Subnet configurations for each VPC
  subnet_configs = {
    for vpc_key, vpc in local.vpcs : vpc_key => {
      public_subnets = [
        for i, az in local.azs : cidrsubnet(vpc.cidr, 8, i + 1)
      ]
      private_subnets = [
        for i, az in local.azs : cidrsubnet(vpc.cidr, 8, i + 11)
      ]
      database_subnets = [
        for i, az in local.azs : cidrsubnet(vpc.cidr, 8, i + 21)
      ]
      tgw_subnets = [
        for i, az in local.azs : cidrsubnet(vpc.cidr, 8, i + 31)
      ]
    }
  }

  # VPC endpoints for shared VPC
  vpc_endpoints = {
    s3 = {
      service             = "s3"
      vpc_endpoint_type   = "Gateway"
      route_table_ids     = []
    }
    dynamodb = {
      service             = "dynamodb"
      vpc_endpoint_type   = "Gateway"
      route_table_ids     = []
    }
  }
} 