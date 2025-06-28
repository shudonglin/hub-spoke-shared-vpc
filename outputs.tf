output "vpc_ids" {
  description = "Map of VPC names to IDs"
  value = {
    for k, v in aws_vpc.vpcs : k => v.id
  }
}

output "vpc_cidrs" {
  description = "Map of VPC names to CIDR blocks"
  value = {
    for k, v in local.vpcs : k => v.cidr
  }
}

output "public_subnet_ids" {
  description = "Map of public subnet identifiers to IDs"
  value = {
    for k, v in aws_subnet.public_subnets : k => v.id
  }
}

output "private_subnet_ids" {
  description = "Map of private subnet identifiers to IDs"
  value = {
    for k, v in aws_subnet.private_subnets : k => v.id
  }
}

output "database_subnet_ids" {
  description = "Map of database subnet identifiers to IDs"
  value = {
    for k, v in aws_subnet.database_subnets : k => v.id
  }
}

output "tgw_subnet_ids" {
  description = "Map of Transit Gateway subnet identifiers to IDs"
  value = {
    for k, v in aws_subnet.tgw_subnets : k => v.id
  }
}

output "transit_gateway_id" {
  description = "ID of the Transit Gateway"
  value       = aws_ec2_transit_gateway.tgw.id
}

output "transit_gateway_route_table_ids" {
  description = "Map of Transit Gateway route table names to IDs"
  value = {
    shared = aws_ec2_transit_gateway_route_table.shared_rt.id
    spoke  = aws_ec2_transit_gateway_route_table.spoke_rt.id
  }
}

output "nat_gateway_ids" {
  description = "Map of NAT Gateway identifiers to IDs"
  value = {
    for k, v in aws_nat_gateway.nat_gws : k => v.id
  }
}

output "internet_gateway_ids" {
  description = "Map of Internet Gateway VPC names to IDs"
  value = {
    for k, v in aws_internet_gateway.igws : k => v.id
  }
}

output "route53_private_zone_id" {
  description = "ID of the Route53 private hosted zone"
  value       = aws_route53_zone.private_zone.zone_id
}

output "route53_private_zone_name" {
  description = "Name of the Route53 private hosted zone"
  value       = aws_route53_zone.private_zone.name
}

output "route53_resolver_endpoint_ids" {
  description = "Map of Route53 resolver endpoint names to IDs"
  value = {
    inbound  = aws_route53_resolver_endpoint.inbound.id
    outbound = aws_route53_resolver_endpoint.outbound.id
  }
}

output "vpc_endpoint_ids" {
  description = "Map of VPC endpoint names to IDs"
  value = merge(
    {
      s3       = aws_vpc_endpoint.s3.id
      dynamodb = aws_vpc_endpoint.dynamodb.id
    },
    {
      for k, v in aws_vpc_endpoint.interface_endpoints : k => v.id
    }
  )
}

output "security_group_ids" {
  description = "Map of security group names to IDs"
  value = {
    resolver_sg      = aws_security_group.resolver_sg.id
    vpc_endpoints_sg = aws_security_group.vpc_endpoints_sg.id
  }
}

output "availability_zones" {
  description = "List of availability zones used"
  value       = local.azs
}

output "test_instance" {
  description = "Test instance information"
  value = var.create_test_instance ? {
    id              = aws_instance.test_instance[0].id
    private_ip      = aws_instance.test_instance[0].private_ip
    vpc             = var.test_instance_vpc
    dns_name        = "test-${var.test_instance_vpc}.${var.domain_name}"
    ssh_command     = "aws ssm start-session --target ${aws_instance.test_instance[0].id}"
    test_url        = "http://${aws_instance.test_instance[0].private_ip}"
    connectivity_tests = [
      "ping ${aws_instance.test_instance[0].private_ip}",
      "curl http://${aws_instance.test_instance[0].private_ip}",
      "nslookup test-${var.test_instance_vpc}.${var.domain_name}"
    ]
  } : null
} 