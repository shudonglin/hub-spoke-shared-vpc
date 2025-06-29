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

# Install and configure nginx web server for WAF testing
amazon-linux-extras install -y nginx1

# Create main website
cat > /usr/share/nginx/html/index.html << 'HTML'
<html><head><title>Hub-Spoke Web App</title><style>body{font-family:Arial;margin:20px;background:#f4f4f4}.container{background:white;padding:20px;border-radius:5px}.info{background:#e7f3ff;padding:10px;margin:10px 0}</style></head><body><div class="container"><h1>🛡️ Hub-Spoke Web Application</h1><div class="info"><h3>Instance Info</h3><p><strong>Instance ID:</strong> <span id="iid">Loading...</span></p><p><strong>Private IP:</strong> <span id="pip">Loading...</span></p><p><strong>VPC:</strong> spoke1</p></div><h3>WAF Test Links</h3><ul><li><a href="/admin">Admin Panel</a></li><li><a href="/api/users">API</a></li><li><a href="/health">Health</a></li></ul><form method="POST" action="/test-form"><input type="text" name="user" placeholder="admin' OR '1'='1"><button>Test WAF</button></form></div><script>fetch('http://169.254.169.254/latest/meta-data/instance-id').then(r=>r.text()).then(d=>document.getElementById('iid').textContent=d);fetch('http://169.254.169.254/latest/meta-data/local-ipv4').then(r=>r.text()).then(d=>document.getElementById('pip').textContent=d);</script></body></html>
HTML

# Create test endpoints
mkdir -p /usr/share/nginx/html/{admin,api,health}
echo '<h1>Admin Panel</h1><p>WAF should block this!</p>' > /usr/share/nginx/html/admin/index.html
echo '<h1>User API</h1><p>Status: Active</p>' > /usr/share/nginx/html/api/index.html
echo '{"status":"healthy","service":"hub-spoke-web"}' > /usr/share/nginx/html/health/index.html

# Configure nginx
systemctl start nginx
systemctl enable nginx

# Create nginx config
cat > /etc/nginx/conf.d/default.conf << 'NGINX'
server {
    listen 80;
    root /usr/share/nginx/html;
    location /health { return 200 '{"status":"healthy","vpc":"spoke1"}'; }
    location /test-form { return 200 '<h1>WAF Test</h1>'; }
    location / { try_files $uri $uri/ =404; }
}
NGINX

# Restart nginx to apply config
systemctl restart nginx

# Create connectivity test script
cat > /home/ec2-user/test-connectivity.sh << 'SCRIPT'
#!/bin/bash
echo "=== Connectivity Test from spoke1 VPC ==="
echo "Current instance IP: $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)"
echo ""

echo "=== DNS Resolution Test ==="
echo "Testing DNS for test-spoke2..."
nslookup test-spoke2.${DOMAIN_NAME} || echo "DNS lookup failed for test-spoke2"
echo ""

echo "=== HTTP Test ==="
echo "Testing HTTP to test-spoke2..."
curl -s --connect-timeout 5 http://test-spoke2.${DOMAIN_NAME} || echo "HTTP connection failed to test-spoke2"
echo ""

echo "=== Cross-VPC connectivity configured via Transit Gateway ==="
SCRIPT

chmod +x /home/ec2-user/test-connectivity.sh
chown ec2-user:ec2-user /home/ec2-user/test-connectivity.sh 