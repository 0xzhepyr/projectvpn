#!/bin/bash
# 🚀 Azure VPS VPN Server Setup Script
# Automated setup for Shadowsocks + HTTP proxy on Azure Ubuntu VPS

set -e

echo "🚀 SecureVPN Pro - Azure VPS Setup"
echo "=================================="
echo "Setting up your Azure VPS as VPN server..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get Azure region automatically
AZURE_REGION=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01")
SERVER_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)

echo -e "${BLUE}📍 Azure Region: $AZURE_REGION${NC}"
echo -e "${BLUE}📍 Server IP: $SERVER_IP${NC}"

# Generate secure passwords
SHADOWSOCKS_PASSWORD=$(openssl rand -base64 32)
HTTP_PROXY_PASSWORD=$(openssl rand -base64 16)

echo -e "${YELLOW}🔑 Generated Shadowsocks password: $SHADOWSOCKS_PASSWORD${NC}"
echo -e "${YELLOW}🔑 Generated HTTP proxy password: $HTTP_PROXY_PASSWORD${NC}"

# Update system
echo -e "${BLUE}📦 Updating system packages...${NC}"
apt update && apt upgrade -y

# Install required packages
echo -e "${BLUE}🛠️ Installing dependencies...${NC}"
apt install -y wget curl unzip nginx certbot python3-certbot-nginx htop ufw fail2ban

# Install Shadowsocks-rust (fastest implementation)
echo -e "${BLUE}⬇️ Installing Shadowsocks-rust...${NC}"
SHADOWSOCKS_VERSION="1.18.0"
wget https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${SHADOWSOCKS_VERSION}/shadowsocks-v${SHADOWSOCKS_VERSION}.x86_64-unknown-linux-gnu.tar.xz
tar -xf shadowsocks-v${SHADOWSOCKS_VERSION}.x86_64-unknown-linux-gnu.tar.xz
cp ssserver sslocal /usr/local/bin/
chmod +x /usr/local/bin/ssserver /usr/local/bin/sslocal
rm shadowsocks-v${SHADOWSOCKS_VERSION}.x86_64-unknown-linux-gnu.tar.xz ss*

# Create Shadowsocks config directory
mkdir -p /etc/shadowsocks

# Create Shadowsocks server config
cat > /etc/shadowsocks/config.json << EOF
{
    "server": "0.0.0.0",
    "server_port": 8388,
    "password": "$SHADOWSOCKS_PASSWORD",
    "timeout": 300,
    "method": "aes-256-gcm",
    "fast_open": true,
    "mode": "tcp_and_udp",
    "no_delay": true
}
EOF

# Create Shadowsocks systemd service
cat > /etc/systemd/system/shadowsocks.service << EOF
[Unit]
Description=Shadowsocks Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ssserver -c /etc/shadowsocks/config.json
Restart=always
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Install and setup HTTP proxy (for fallback)
echo -e "${BLUE}🔧 Setting up HTTP proxy...${NC}"
apt install -y squid apache2-utils

# Create HTTP proxy user
htpasswd -bc /etc/squid/passwd vpnuser $HTTP_PROXY_PASSWORD

# Configure Squid proxy
cat > /etc/squid/squid.conf << EOF
# Azure VPS HTTP Proxy Configuration
http_port 3128

# Authentication
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Azure VPN Proxy
auth_param basic credentialsttl 2 hours

# Access control
acl authenticated proxy_auth REQUIRED
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10

# Allow authenticated users
http_access allow authenticated
http_access allow localnet
http_access deny all

# Hide server info
httpd_suppress_version_string on
via off
forwarded_for off

# Cache settings
cache deny all

# DNS settings
dns_nameservers 8.8.8.8 1.1.1.1

# Logs
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
EOF

# Setup health check endpoint
echo -e "${BLUE}🏥 Setting up health check endpoint...${NC}"
cat > /var/www/html/health << EOF
{
    "status": "healthy",
    "server": "azure-vpn",
    "region": "$AZURE_REGION",
    "timestamp": $(date +%s),
    "services": {
        "shadowsocks": "8388",
        "http_proxy": "3128",
        "health_check": "80"
    }
}
EOF

# Configure Nginx for health checks and stats
cat > /etc/nginx/sites-available/vpn-health << EOF
server {
    listen 80;
    server_name _;
    
    # Health check endpoint
    location /health {
        add_header Content-Type application/json;
        add_header Access-Control-Allow-Origin *;
        alias /var/www/html/health;
    }
    
    # IP check endpoint
    location /ip {
        add_header Content-Type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"ip": "\$remote_addr", "server": "azure-vpn", "region": "$AZURE_REGION"}';
    }
    
    # Speed test endpoint
    location /speedtest {
        add_header Content-Type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"message": "Azure VPN speed test", "size": 1024, "timestamp": $(date +%s)}';
    }
    
    # Basic stats
    location /stats {
        add_header Content-Type text/plain;
        return 200 "Azure VPN Server Status: OK\nRegion: $AZURE_REGION\nServices: Shadowsocks(8388), HTTP Proxy(3128)";
    }
}
EOF

ln -sf /etc/nginx/sites-available/vpn-health /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Configure firewall
echo -e "${BLUE}🔥 Configuring firewall...${NC}"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow essential services
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (health checks)
ufw allow 443/tcp   # HTTPS
ufw allow 8388/tcp  # Shadowsocks TCP
ufw allow 8388/udp  # Shadowsocks UDP
ufw allow 3128/tcp  # HTTP Proxy

# Enable firewall
echo "y" | ufw enable

# Configure fail2ban for SSH protection
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
EOF

# Optimize network performance for VPN
echo -e "${BLUE}⚡ Optimizing network performance...${NC}"
cat >> /etc/sysctl.conf << EOF

# Azure VPN Optimizations
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 30000
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.ip_forward = 1
EOF

sysctl -p

# Start and enable services
echo -e "${BLUE}🚀 Starting services...${NC}"
systemctl daemon-reload
systemctl enable shadowsocks squid nginx fail2ban
systemctl start shadowsocks squid nginx fail2ban

# Create connection info file
cat > /root/vpn-connection-info.json << EOF
{
    "server_info": {
        "provider": "Azure",
        "region": "$AZURE_REGION",
        "ip": "$SERVER_IP",
        "setup_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    },
    "shadowsocks": {
        "server": "$SERVER_IP",
        "server_port": 8388,
        "password": "$SHADOWSOCKS_PASSWORD",
        "method": "aes-256-gcm",
        "protocol": "shadowsocks"
    },
    "http_proxy": {
        "server": "$SERVER_IP",
        "port": 3128,
        "username": "vpnuser",
        "password": "$HTTP_PROXY_PASSWORD",
        "protocol": "http"
    },
    "health_endpoints": {
        "health_check": "http://$SERVER_IP/health",
        "ip_check": "http://$SERVER_IP/ip",
        "speed_test": "http://$SERVER_IP/speedtest",
        "stats": "http://$SERVER_IP/stats"
    }
}
EOF

# Check service status
echo -e "${GREEN}🏥 Checking service status...${NC}"
echo "Shadowsocks status:"
systemctl status shadowsocks --no-pager -l

echo "HTTP Proxy status:"
systemctl status squid --no-pager -l

echo "Nginx status:"
systemctl status nginx --no-pager -l

# Test endpoints
echo -e "${GREEN}🧪 Testing endpoints...${NC}"
curl -s http://localhost/health | python3 -m json.tool
curl -s http://localhost/ip

# Display connection info
echo ""
echo -e "${GREEN}🎉 Azure VPS VPN Server Setup Complete!${NC}"
echo "======================================"
echo -e "${YELLOW}📍 Server IP: $SERVER_IP${NC}"
echo -e "${YELLOW}📍 Azure Region: $AZURE_REGION${NC}"
echo ""
echo -e "${BLUE}🔌 Shadowsocks Connection:${NC}"
echo "  Server: $SERVER_IP"
echo "  Port: 8388"
echo "  Password: $SHADOWSOCKS_PASSWORD"
echo "  Method: aes-256-gcm"
echo ""
echo -e "${BLUE}🔌 HTTP Proxy Connection:${NC}"
echo "  Server: $SERVER_IP"
echo "  Port: 3128"
echo "  Username: vpnuser"
echo "  Password: $HTTP_PROXY_PASSWORD"
echo ""
echo -e "${BLUE}🏥 Health Check Endpoints:${NC}"
echo "  Health: http://$SERVER_IP/health"
echo "  IP Check: http://$SERVER_IP/ip"
echo "  Stats: http://$SERVER_IP/stats"
echo ""
echo -e "${GREEN}📋 Connection details saved to: /root/vpn-connection-info.json${NC}"
echo ""
echo -e "${YELLOW}✅ Your Azure VPS is now ready for Chrome Extension!${NC}"
echo -e "${YELLOW}✅ Next: Update your Chrome extension with these connection details${NC}"

# Save connection details for Chrome extension
cat > /root/chrome-extension-config.js << EOF
// Azure VPS Configuration for Chrome Extension
const AZURE_VPS_CONFIG = {
    server: {
        name: 'Azure ${AZURE_REGION}',
        host: '$SERVER_IP',
        region: '$AZURE_REGION',
        flag: '☁️',
        provider: 'azure'
    },
    shadowsocks: {
        host: '$SERVER_IP',
        port: 8388,
        password: '$SHADOWSOCKS_PASSWORD',
        method: 'aes-256-gcm'
    },
    http_proxy: {
        host: '$SERVER_IP',
        port: 3128,
        username: 'vpnuser',
        password: '$HTTP_PROXY_PASSWORD'
    },
    health_endpoints: {
        health: 'http://$SERVER_IP/health',
        ip: 'http://$SERVER_IP/ip',
        speedtest: 'http://$SERVER_IP/speedtest'
    }
};
EOF

echo -e "${GREEN}📱 Chrome extension config saved to: /root/chrome-extension-config.js${NC}" 
