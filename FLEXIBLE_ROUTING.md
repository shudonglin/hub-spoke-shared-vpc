# 🔄 Flexible ALB Routing Configuration

## Overview

The ALB configuration now supports **flexible routing** to both spoke VPCs:
- **Spoke1**: Always accessible (primary web server)
- **Spoke2**: Optionally accessible via ALB (controlled by `enable_spoke2_alb_access`)

## 🎛️ Configuration Control

### Enable/Disable Spoke2 ALB Access

```hcl
# Enable spoke2 access via ALB (default: true)
enable_spoke2_alb_access = true

# Disable spoke2 ALB access (spoke2 remains independent)
enable_spoke2_alb_access = false
```

## 🚦 Routing Behavior

### When `enable_spoke2_alb_access = true` (Default)

```
Internet → ALB/WAF → Spoke1 (default) OR Spoke2 (specific paths)
```

#### **Traffic Distribution:**
- **Default Traffic**: `http://ALB_DNS/` → Spoke1 (nginx)
- **Spoke2 Paths**: `http://ALB_DNS/spoke2*` → Spoke2 (apache)
- **Alternative Paths**: `http://ALB_DNS/test2*` → Spoke2
- **Secondary Paths**: `http://ALB_DNS/secondary*` → Spoke2

#### **Target Groups Created:**
- ✅ `hub-spoke-vpc-spoke1-tg` (Primary)
- ✅ `hub-spoke-vpc-spoke2-tg` (Secondary)

### When `enable_spoke2_alb_access = false`

```
Internet → ALB/WAF → Spoke1 only
Spoke2 → Independent (DNS access only)
```

#### **Traffic Distribution:**
- **All Traffic**: `http://ALB_DNS/*` → Spoke1 (nginx)
- **Spoke2**: Direct access only via `test-spoke2.gic-private.local`

#### **Target Groups Created:**
- ✅ `hub-spoke-vpc-spoke1-tg` (Primary only)
- ❌ No ALB target group for spoke2

## 🌐 Access Methods

### **Spoke1 Access** (Always Available)

#### Public Access (ALB)
```bash
# Main application (nginx with WAF testing)
curl http://<ALB_DNS_NAME>
curl http://<ALB_DNS_NAME>/health
curl http://<ALB_DNS_NAME>/admin  # Should be blocked by WAF
```

#### Internal Access
```bash
# Direct DNS access
curl http://test-spoke1.gic-private.local
ping test-spoke1.gic-private.local
```

### **Spoke2 Access** (Flexible)

#### When ALB Access Enabled (`enable_spoke2_alb_access = true`)

**Public Access (ALB):**
```bash
# Path-based routing to spoke2
curl http://<ALB_DNS_NAME>/spoke2
curl http://<ALB_DNS_NAME>/test2
curl http://<ALB_DNS_NAME>/secondary

# Health check for spoke2
curl http://<ALB_DNS_NAME>/spoke2/health
```

**Internal Access:**
```bash
# Direct DNS access (always available)
curl http://test-spoke2.gic-private.local
ping test-spoke2.gic-private.local
```

#### When ALB Access Disabled (`enable_spoke2_alb_access = false`)

**Internal Access Only:**
```bash
# Direct DNS access only
curl http://test-spoke2.gic-private.local
ping test-spoke2.gic-private.local

# ALB paths return 503 (no target group)
curl http://<ALB_DNS_NAME>/spoke2  # Returns 503 Service Unavailable
```

## 🏗️ Use Cases

### **Development Environment** (`enable_spoke2_alb_access = true`)
- **Spoke1**: Main application under development
- **Spoke2**: Secondary application or different environment
- **Benefit**: Both accessible via single ALB with WAF protection

### **Production Environment** (`enable_spoke2_alb_access = false`)
- **Spoke1**: Customer-facing web application
- **Spoke2**: Internal tools, monitoring, or testing (independent)
- **Benefit**: Clear separation, spoke2 not exposed publicly

### **Testing Environment** (`enable_spoke2_alb_access = true`)
- **Spoke1**: Application under test
- **Spoke2**: Test environment or different version
- **Benefit**: A/B testing, blue-green deployments

### **Multi-Application Setup** (`enable_spoke2_alb_access = true`)
- **Spoke1**: Primary application (e.g., main website)
- **Spoke2**: Secondary application (e.g., API, admin panel)
- **Benefit**: Multiple applications behind single ALB/WAF

## 🔧 Implementation Details

### **Target Group Creation Logic**
```hcl
# Creates target groups conditionally
for_each = [
  for vpc in var.test_instance_vpcs : vpc 
  if vpc == "spoke1" || (vpc == "spoke2" && var.enable_spoke2_alb_access)
]
```

### **Listener Rules (When Spoke2 Enabled)**
```hcl
# Path-based routing
condition {
  path_pattern {
    values = ["/spoke2*", "/test2*", "/secondary*"]
  }
}

# Optional: Host-based routing
condition {
  host_header {
    values = ["spoke2.*", "test2.*", "secondary.*"]
  }
}
```

### **Health Checks**
- **Spoke1**: Always enabled (`/health`)
- **Spoke2**: Only when ALB access enabled (`/health`)

## 📊 Traffic Flow Diagrams

### **Flexible Mode** (`enable_spoke2_alb_access = true`)
```
Internet
    ↓
AWS WAF (Shared VPC)
    ↓
Application Load Balancer
    ↓
┌─────────────────┬─────────────────┐
│ Default Path    │ /spoke2* paths  │
│       ↓         │       ↓         │
│   Spoke1 VPC    │   Spoke2 VPC    │
│ (nginx - TG1)   │ (apache - TG2)  │
└─────────────────┴─────────────────┘
```

### **Independent Mode** (`enable_spoke2_alb_access = false`)
```
Internet                Internal Network
    ↓                         ↓
AWS WAF (Shared VPC)    test-spoke2.gic-private.local
    ↓                         ↓
Application Load Balancer     │
    ↓                         │
Spoke1 VPC                Spoke2 VPC
(nginx - TG1)             (apache - independent)
```

## 🔀 Migration Between Modes

### **Enable Spoke2 ALB Access**
```hcl
# In terraform.tfvars
enable_spoke2_alb_access = true
```

```bash
terraform plan   # Review changes
terraform apply  # Creates spoke2 target group and rules
```

### **Disable Spoke2 ALB Access**
```hcl
# In terraform.tfvars
enable_spoke2_alb_access = false
```

```bash
terraform plan   # Review changes
terraform apply  # Removes spoke2 target group and rules
```

## 🛡️ Security Considerations

### **WAF Protection**
- Both spoke1 and spoke2 (when enabled) receive WAF protection
- All AWS managed rules apply to both targets
- Rate limiting applies to both targets

### **Network Security**
- Security groups allow ALB access to both spoke VPCs
- Transit Gateway routing enables cross-VPC communication
- Both instances remain in private subnets

### **Access Control**
- Spoke2 ALB access can be disabled for security isolation
- Internal DNS access always available for administration
- Fine-grained path-based routing control

## 📈 Monitoring

### **CloudWatch Metrics**
- Target group health for both spoke1 and spoke2
- Request distribution between target groups
- WAF metrics apply to all traffic

### **ALB Access Logs**
- Show traffic distribution between spoke1 and spoke2
- Path-based routing analytics
- Performance comparison between targets

---

This flexible configuration provides the best of both worlds: **centralized security** with **architectural flexibility**. 