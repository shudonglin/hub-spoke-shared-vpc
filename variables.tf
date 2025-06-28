variable "aws_region" {
  description = "AWS Region to create the environment"
  type        = string
  default     = "ap-southeast-1"
}

variable "project_name" {
  description = "Project name used as identifier for resources"
  type        = string
  default     = "hub-spoke-vpc"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "availability_zones" {
  description = "List of availability zones to use"
  type        = list(string)
  default     = []
}

variable "shared_vpc_cidr" {
  description = "CIDR block for the shared VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "spoke_vpc_cidrs" {
  description = "CIDR blocks for spoke VPCs"
  type        = map(string)
  default = {
    spoke1 = "10.1.0.0/16"
    spoke2 = "10.2.0.0/16"
  }
}

variable "domain_name" {
  description = "Domain name for Route53 private hosted zone"
  type        = string
  default     = "internal.local"
}

variable "enable_dns_hostnames" {
  description = "Enable DNS hostnames in VPC"
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Enable DNS support in VPC"
  type        = bool
  default     = true
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use a single NAT Gateway for all private subnets"
  type        = bool
  default     = false
}

variable "tags" {
  description = "A map of tags to assign to resources"
  type        = map(string)
  default     = {}
}

variable "create_test_instance" {
  description = "Create a test EC2 instance for connectivity testing"
  type        = bool
  default     = true
}

variable "test_instance_type" {
  description = "Instance type for the test EC2 instance"
  type        = string
  default     = "t3.micro"
}

variable "test_instance_vpc" {
  description = "VPC to deploy the test instance in (shared, spoke1, or spoke2)"
  type        = string
  default     = "spoke1"
  validation {
    condition     = contains(["shared", "spoke1", "spoke2"], var.test_instance_vpc)
    error_message = "Test instance VPC must be one of: shared, spoke1, spoke2."
  }
} 