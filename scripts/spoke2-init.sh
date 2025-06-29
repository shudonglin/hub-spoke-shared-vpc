#!/bin/bash
yum update -y
yum install -y awscli htop curl wget telnet nmap-ncat bind-utils

# Install CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
rpm -U ./amazon-cloudwatch-agent.rpm

# Create simplified CloudWatch agent configuration
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'CWCONFIG'
{"agent":{"metrics_collection_interval":60,"run_as_user":"cwagent"},"metrics":{"namespace":"CWAgent","metrics_collected":{"cpu":{"measurement":["cpu_usage_idle","cpu_usage_user","cpu_usage_system"],"metrics_collection_interval":60,"totalcpu":false},"disk":{"measurement":["used_percent"],"metrics_collection_interval":60,"resources":["*"]},"mem":{"measurement":["mem_used_percent","mem_available_percent"],"metrics_collection_interval":60}}}}
CWCONFIG

# Start and enable CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config \
  -m ec2 \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
  -s

systemctl enable amazon-cloudwatch-agent

# Install simple web server for spoke2 (connectivity testing)
yum install -y httpd

# Create simple test page
cat > /var/www/html/index.html << 'HTML'
<html><head><title>Test Instance - spoke2</title><style>body{font-family:Arial;margin:40px;background:#f0f8ff}.container{background:white;padding:30px;border-radius:8px}.header{color:#2c5282;border-bottom:2px solid #3182ce;padding-bottom:10px}</style></head><body><div class="container"><h1 class="header">🔗 Test Instance - spoke2 VPC</h1><p><strong>Instance ID:</strong> <span id="iid">Loading...</span></p><p><strong>Private IP:</strong> <span id="pip">Loading...</span></p><p><strong>VPC:</strong> spoke2</p><p><strong>Purpose:</strong> Connectivity Testing</p><h3>Status</h3><p>✅ This instance is independent for cross-VPC testing</p><h3>Test Endpoints</h3><ul><li><a href="/health">Health Check</a></li><li><a href="/info">System Info</a></li></ul></div><script>fetch('http://169.254.169.254/latest/meta-data/instance-id').then(r=>r.text()).then(d=>document.getElementById('iid').textContent=d);fetch('http://169.254.169.254/latest/meta-data/local-ipv4').then(r=>r.text()).then(d=>document.getElementById('pip').textContent=d);</script></body></html>
HTML

# Create health check endpoint
mkdir -p /var/www/html/health
echo '{"status":"healthy","service":"test-instance","vpc":"spoke2"}' > /var/www/html/health/index.html

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

# Create connectivity test script
cat > /home/ec2-user/test-connectivity.sh << 'SCRIPT'
#!/bin/bash
echo "=== Connectivity Test from spoke2 VPC ==="
echo "Current instance IP: $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)"
echo ""

echo "=== DNS Resolution Test ==="
echo "Testing DNS for test-spoke1..."
nslookup test-spoke1.${DOMAIN_NAME} || echo "DNS lookup failed for test-spoke1"
echo ""

echo "=== HTTP Test ==="
echo "Testing HTTP to test-spoke1..."
curl -s --connect-timeout 5 http://test-spoke1.${DOMAIN_NAME} || echo "HTTP connection failed to test-spoke1"
echo ""

echo "=== Cross-VPC connectivity configured via Transit Gateway ==="
SCRIPT

chmod +x /home/ec2-user/test-connectivity.sh
chown ec2-user:ec2-user /home/ec2-user/test-connectivity.sh 