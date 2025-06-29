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
  default     = true
}

variable "tags" {
  description = "A map of tags to assign to resources"
  type        = map(string)
  default     = {}
}

variable "create_test_instances" {
  description = "Create test EC2 instances for connectivity testing"
  type        = bool
  default     = true
}

variable "test_instance_type" {
  description = "Instance type for the test EC2 instances"
  type        = string
  default     = "t2.micro"
}

variable "test_instance_vpcs" {
  description = "List of VPCs to deploy test instances in"
  type        = list(string)
  default     = ["spoke1", "spoke2"]
  validation {
    condition     = alltrue([for vpc in var.test_instance_vpcs : contains(["shared", "spoke1", "spoke2"], vpc)])
    error_message = "Test instance VPCs must be from: shared, spoke1, spoke2."
  }
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for all VPCs"
  type        = bool
  default     = true
}

variable "flow_logs_retention_days" {
  description = "CloudWatch Logs retention period for VPC Flow Logs (days)"
  type        = number
  default     = 7
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.flow_logs_retention_days)
    error_message = "Retention days must be one of the valid CloudWatch Logs retention periods."
  }
}

variable "create_bastion_host" {
  description = "Create a bastion host for SSH access to test instances"
  type        = bool
  default     = false
}

variable "bastion_instance_type" {
  description = "Instance type for the bastion host"
  type        = string
  default     = "t2.micro"
}

variable "ssh_allowed_cidr_blocks" {
  description = "CIDR blocks allowed to SSH to bastion host"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Change this to your IP for security
}

variable "enable_spoke_to_spoke_communication" {
  description = "Enable direct communication between spoke VPCs (full mesh)"
  type        = bool
  default     = true
}

# ===============================
# WAF Configuration
# ===============================

variable "enable_waf" {
  description = "Enable AWS WAF with Application Load Balancer"
  type        = bool
  default     = true
}



variable "waf_rate_limit" {
  description = "Rate limit for WAF (requests per 5 minutes)"
  type        = number
  default     = 2000
}

variable "waf_blocked_countries" {
  description = "List of country codes to block (ISO 3166-1 alpha-2)"
  type        = list(string)
  default     = []
  # Example: ["CN", "RU", "KP"] to block China, Russia, North Korea
}

variable "waf_allowed_ips" {
  description = "List of IP addresses/CIDR blocks to always allow"
  type        = list(string)
  default     = []
  # Example: ["1.2.3.4/32", "10.0.0.0/8"]
}

variable "waf_blocked_ips" {
  description = "List of IP addresses/CIDR blocks to block"
  type        = list(string)
  default     = []
}

variable "enable_aws_managed_rules" {
  description = "Enable AWS managed rule sets"
  type = object({
    core_rule_set           = optional(bool, true)
    admin_protection        = optional(bool, true)
    known_bad_inputs        = optional(bool, true)
    sql_injection          = optional(bool, true)
    linux_operating_system = optional(bool, true)
    unix_operating_system  = optional(bool, false)
  })
  default = {}
}

# Removed enable_spoke2_alb_access variable - spoke2 is now completely independent
# ALB is only in spoke1 VPC for direct access to app1 