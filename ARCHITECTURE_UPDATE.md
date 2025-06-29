# 🏗️ Updated Hub-Spoke Architecture

## Architecture Changes

The ALB configuration has been updated to reflect a more realistic architecture:

### **Before** (All instances behind ALB)
```
ALB → [spoke1, spoke2] (both behind load balancer)
```

### **After** (Spoke1 only behind ALB) ✅
```
ALB → spoke1 (web application)
spoke2 (independent test instance)
```

## 🎯 Current Architecture

### **Spoke1 VPC - Web Application**
- **Purpose**: Production web server
- **Technology**: Nginx with WAF testing endpoints  
- **Load Balancer**: ✅ Behind ALB with WAF protection
- **Access Methods**:
  - Public: `http://<ALB_DNS_NAME>` (with WAF protection)
  - Internal: `http://test-spoke1.gic-private.local`
- **Features**:
  - Full web application with WAF testing
  - Admin panel, API endpoints, security tests
  - Health checks for ALB
  - Detailed logging

### **Spoke2 VPC - Test Instance**
- **Purpose**: Connectivity and DNS testing
- **Technology**: Simple Apache server
- **Load Balancer**: ❌ Not behind ALB (independent)
- **Access Methods**:
  - Internal only: `http://test-spoke2.gic-private.local`
  - No public access (not behind ALB)
- **Features**:
  - Basic connectivity testing
  - DNS resolution testing
  - Cross-VPC communication tests

## 🔄 Traffic Flow

### **Public Web Traffic**
```
Internet → ALB (Shared VPC) → WAF → Transit Gateway → Spoke1 VPC → Nginx
```

### **Internal Testing** 
```
Spoke2 → Transit Gateway → Spoke1 (DNS + HTTP + Ping)
```

## 🧪 Testing Scenarios

### **1. Web Application Testing (Spoke1)**
```bash
# Public access via ALB
curl http://<ALB_DNS_NAME>
curl http://<ALB_DNS_NAME>/health
curl http://<ALB_DNS_NAME>/admin  # Should be blocked by WAF

# Internal access
curl http://test-spoke1.gic-private.local
```

### **2. Connectivity Testing (From Spoke2)**
```bash
# Connect to spoke2 test instance
aws ssm start-session --target <SPOKE2_INSTANCE_ID>

# Test DNS resolution
nslookup test-spoke1.gic-private.local
nslookup test-spoke2.gic-private.local

# Test connectivity to spoke1
ping test-spoke1.gic-private.local
curl http://test-spoke1.gic-private.local

# Run connectivity test script
bash /home/ec2-user/test-connectivity.sh
```

### **3. DNS Troubleshooting**
```bash
# If DNS fails, run troubleshooting scripts
bash fix-dns.sh
bash dns-troubleshoot.sh
```

## 📊 Benefits of This Architecture

### **Spoke1 (Web Server)**
- ✅ **Security**: Protected by WAF and centralized in shared VPC
- ✅ **Scalability**: Can add more instances behind ALB
- ✅ **Monitoring**: ALB health checks and detailed logging
- ✅ **Cost Effective**: Single target group for web workload

### **Spoke2 (Test Instance)**  
- ✅ **Independence**: Not affected by ALB changes
- ✅ **Flexibility**: Can test different applications without ALB
- ✅ **Simplicity**: Direct access for testing scenarios
- ✅ **Realistic**: Simulates client/test environments

## 🔧 Configuration Files Updated

- `waf.tf`: ALB targets only spoke1
- `outputs.tf`: Clear separation of ALB vs direct access
- `main.tf`: User data already configured correctly
- Architecture reflects real-world patterns

## 💡 Use Cases

### **Production Scenario**
- **Spoke1**: Customer-facing web application
- **Spoke2**: Internal tools, monitoring, or different application

### **Testing Scenario**  
- **Spoke1**: Application under test
- **Spoke2**: Test client or load generator

### **Development Scenario**
- **Spoke1**: Development web server  
- **Spoke2**: Development tools and utilities

---

This architecture provides a clean separation between the production web application (spoke1) and testing infrastructure (spoke2), making it more realistic and maintainable. 