# Hub and Spoke VPC Architecture with Terraform

This Terraform configuration creates a hub and spoke VPC architecture on AWS with shared services and DNS resolution.

## Architecture Overview

This configuration creates:

- **3 VPCs**: 1 shared services VPC (hub) and 2 spoke VPCs
- **Transit Gateway**: Central connectivity hub for inter-VPC communication
- **Route53**: Private hosted zone with DNS resolution across all VPCs
- **VPC Endpoints**: Centralized AWS service gateway endpoints (S3, DynamoDB) in the shared VPC
- **Multi-AZ Deployment**: Each VPC spans 3 availability zones

## VPC Structure

Each VPC includes:
- **3 Public Subnets**: One per availability zone with internet access
- **3 Private Subnets**: One per availability zone for application workloads
- **3 Database Subnets**: One per availability zone for database resources
- **3 Transit Gateway Subnets**: One per availability zone for TGW attachments

## Network Topology

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Spoke VPC 1   │    │  Shared VPC     │    │   Spoke VPC 2   │
│   10.1.0.0/16   │    │  (Hub)          │    │   10.2.0.0/16   │
│                 │    │  10.0.0.0/16    │    │                 │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │    Transit Gateway        │
                    │                           │
                    │  • Route Tables           │
                    │  • VPC Attachments        │
                    └───────────────────────────┘
```

## Key Features

### Networking
- **Hub and Spoke Topology**: Centralized shared services with isolated spoke networks
- **Transit Gateway**: Simplified inter-VPC routing and connectivity
- **Multi-AZ High Availability**: Resources distributed across 3 availability zones
- **NAT Gateways**: Outbound internet access for private subnets

### DNS Resolution
- **Route53 Private Hosted Zone**: Centralized DNS resolution
- **Cross-VPC DNS**: DNS queries resolved across all VPCs via resolver endpoints
- **Inbound/Outbound Resolvers**: Bi-directional DNS resolution support

### Security & Monitoring
- **Network Segmentation**: Isolated spoke VPCs with controlled communication
- **Security Groups**: Least privilege access for VPC endpoints and resolvers
- **Private Endpoints**: S3 and DynamoDB access without internet traversal (interface endpoints removed for cost optimization)
- **VPC Flow Logs**: Comprehensive network traffic monitoring with KMS encryption
- **CloudWatch Integration**: Centralized logging with configurable retention periods

### AWS Service Access
- **VPC Endpoints**: Centralized access to AWS services (S3, DynamoDB)
- **Private Connectivity**: No internet traffic for AWS service communication to S3/DynamoDB

### Testing & Validation
- **Multiple Test Instances**: Optional t2.micro instances across multiple VPCs for connectivity testing
- **Cross-VPC Communication**: Automated testing scripts for ping, DNS, and HTTP connectivity
- **SSM Session Manager**: Secure shell access without SSH keys or bastion hosts
- **Built-in Web Server**: Simple HTTP server for testing cross-VPC connectivity
- **DNS Testing**: Route53 records for testing internal DNS resolution
- **Connectivity Test Scripts**: Pre-installed scripts for comprehensive network testing

## Prerequisites

- Terraform >= 1.12.0
- AWS CLI configured with appropriate permissions
- AWS Provider version 6.0.0
- AWS credentials with sufficient permissions for EC2, VPC, Transit Gateway, Route53, and IAM

## Usage

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd hub-spoke-shared-vpc
   ```

2. **Configure variables** (optional):
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your desired values
   ```

3. **Initialize Terraform**:
   ```bash
   terraform init
   ```

4. **Plan the deployment**:
   ```bash
   terraform plan
   ```

5. **Apply the configuration**:
   ```bash
   terraform apply
   ```

## Input Variables

| Variable | Description | Type | Default |
|----------|-------------|------|---------|
| `aws_region` | AWS Region for deployment | `string` | `"ap-southeast-1"` |
| `project_name` | Project name used as identifier | `string` | `"hub-spoke-vpc"` |
| `environment` | Environment name | `string` | `"dev"` |
| `shared_vpc_cidr` | CIDR block for shared VPC | `string` | `"10.0.0.0/16"` |
| `spoke_vpc_cidrs` | Map of spoke VPC CIDR blocks | `map(string)` | See variables.tf |
| `domain_name` | Domain for private hosted zone | `string` | `"internal.local"` |
| `enable_nat_gateway` | Enable NAT Gateway | `bool` | `true` |
| `single_nat_gateway` | Use single NAT Gateway | `bool` | `false` |
| `create_test_instances` | Create test EC2 instances | `bool` | `true` |
| `test_instance_type` | Test instance type | `string` | `"t2.micro"` |
| `test_instance_vpcs` | List of VPCs for test instances | `list(string)` | `["spoke1", "spoke2"]` |
| `enable_vpc_flow_logs` | Enable VPC Flow Logs | `bool` | `true` |
| `flow_logs_retention_days` | CloudWatch retention period | `number` | `7` |

## Outputs

| Output | Description |
|--------|-------------|
| `vpc_ids` | Map of VPC names to IDs |
| `transit_gateway_id` | Transit Gateway ID |
| `route53_private_zone_id` | Private hosted zone ID |
| `vpc_endpoint_ids` | Map of VPC endpoint IDs (S3, DynamoDB) |
| `vpc_flow_logs` | VPC Flow Logs configuration and KMS details |
| `test_instances` | Map of test instances information by VPC |
| `connectivity_test_commands` | Commands for testing cross-VPC connectivity |

## CIDR Allocation

Default CIDR allocation per VPC:

### Shared VPC (10.0.0.0/16)
- Public subnets: 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24
- Private subnets: 10.0.11.0/24, 10.0.12.0/24, 10.0.13.0/24
- Database subnets: 10.0.21.0/24, 10.0.22.0/24, 10.0.23.0/24
- TGW subnets: 10.0.31.0/24, 10.0.32.0/24, 10.0.33.0/24

### Spoke VPC 1 (10.1.0.0/16)
- Public subnets: 10.1.1.0/24, 10.1.2.0/24, 10.1.3.0/24
- Private subnets: 10.1.11.0/24, 10.1.12.0/24, 10.1.13.0/24
- Database subnets: 10.1.21.0/24, 10.1.22.0/24, 10.1.23.0/24
- TGW subnets: 10.1.31.0/24, 10.1.32.0/24, 10.1.33.0/24

### Spoke VPC 2 (10.2.0.0/16)
- Public subnets: 10.2.1.0/24, 10.2.2.0/24, 10.2.3.0/24
- Private subnets: 10.2.11.0/24, 10.2.12.0/24, 10.2.13.0/24
- Database subnets: 10.2.21.0/24, 10.2.22.0/24, 10.2.23.0/24
- TGW subnets: 10.2.31.0/24, 10.2.32.0/24, 10.2.33.0/24

## Routing

### Public Subnets
- Default route (0.0.0.0/0) → Internet Gateway

### Private Subnets
- Default route (0.0.0.0/0) → NAT Gateway
- Cross-VPC routes → Transit Gateway

### Database Subnets
- Cross-VPC routes only → Transit Gateway
- No internet access

### Transit Gateway Routing
- **Shared Route Table**: Associated with shared VPC, propagates spoke VPC routes
- **Spoke Route Table**: Associated with spoke VPCs, propagates shared VPC routes

## DNS Resolution

- **Private Hosted Zone**: `internal.local` (configurable)
- **Inbound Resolver**: Accepts DNS queries from spoke VPCs
- **Outbound Resolver**: Forwards queries to external DNS servers
- **Cross-VPC Resolution**: All VPCs can resolve names in the private zone

## Security Considerations

1. **Network Segmentation**: Spoke VPCs are isolated from each other
2. **Least Privilege**: Security groups allow only necessary traffic
3. **Private Endpoints**: AWS service traffic stays within AWS network
4. **Transit Gateway Route Tables**: Control inter-VPC communication

## Cost Optimization

- NAT Gateways can be configured as single or per-AZ
- Gateway VPC endpoints (S3, DynamoDB) reduce data transfer costs and are free
- Interface VPC endpoints removed to reduce costs (~$22/month savings)
- Transit Gateway consolidates connectivity

## Customization

The configuration is highly customizable:

1. **Modify CIDR blocks** in `terraform.tfvars`
2. **Adjust subnet counts** by changing the AZ count
3. **Add/remove VPC endpoints** in the locals (currently includes S3 and DynamoDB gateway endpoints)
4. **Configure additional security groups** as needed

## Testing Connectivity

After deployment, you can test the infrastructure:

### 1. Connect to Test Instances (Multiple Options)

#### **Option A: SSM Session Manager (Recommended - No SSH needed)**
```bash
# Get instances information
terraform output test_instances

# Connect directly via AWS CLI (most convenient)
aws ssm start-session --target <INSTANCE_ID> --region ap-southeast-1

# Or connect via AWS Console
# Go to: EC2 Console → Instances → Select Instance → Connect → Session Manager
```

#### **Option B: SSH via SSM Port Forwarding (if you prefer SSH)**
```bash
# Forward local port 2222 to instance SSH port 22
aws ssm start-session --target <INSTANCE_ID> \
    --document-name AWS-StartPortForwardingSession \
    --parameters '{"portNumber":["22"],"localPortNumber":["2222"]}' \
    --region ap-southeast-1

# In another terminal, SSH via localhost
ssh -i ~/.ssh/your-key.pem -p 2222 ec2-user@localhost
```

#### **Option C: Instance Connect Endpoint (Alternative)**
```bash
# Direct SSH without permanent EIP (AWS feature)
aws ec2-instance-connect send-ssh-public-key \
    --instance-id <INSTANCE_ID> \
    --instance-os-user ec2-user \
    --ssh-public-key file://~/.ssh/id_rsa.pub \
    --region ap-southeast-1

# Then SSH directly
ssh ec2-user@<PRIVATE_IP>
```

### 2. Test Cross-VPC Connectivity
```bash
# Inside any test instance, run the comprehensive connectivity test
sudo -u ec2-user /home/ec2-user/test-connectivity.sh

# Or test individual components manually:
# Test DNS resolution between VPCs
nslookup test-spoke1.internal.local
nslookup test-spoke2.internal.local

# Test ping connectivity between VPCs  
ping -c 3 test-spoke1.internal.local
ping -c 3 test-spoke2.internal.local

# Test HTTP connectivity between instances
curl http://test-spoke1.internal.local
curl http://test-spoke2.internal.local
```

### 3. Monitor VPC Flow Logs
```bash
# View VPC Flow Logs in CloudWatch
aws logs describe-log-groups --log-group-name-prefix "/aws/vpc/flowlogs"

# Get recent flow logs for a specific VPC
aws logs tail /aws/vpc/flowlogs/spoke1 --follow
```

### 3. Test VPC Endpoints
```bash
# Test S3 endpoint (private gateway endpoint)
aws s3 ls

# Test DynamoDB endpoint (private gateway endpoint)
aws dynamodb list-tables

# Note: SSM uses public endpoints (no private interface endpoints configured)
aws ssm get-parameter --name "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
```

## Clean Up

To destroy the infrastructure:

```bash
terraform destroy
```

## Support

For issues or questions:
1. Check the Terraform plan output for any errors
2. Verify AWS permissions and quota limits
3. Review CloudFormation events in AWS console

## License

This project is licensed under the MIT License - see the LICENSE file for details.
