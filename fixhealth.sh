#!/bin/bash
# 🔧 Fix health endpoint dan ambil connection details

echo "🔧 Fixing Azure VPS health endpoint..."

# Get server info
SERVER_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)
AZURE_REGION=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01" 2>/dev/null || echo "azure-region")

echo "📍 Server IP: $SERVER_IP"
echo "📍 Azure Region: $AZURE_REGION"

# Fix health endpoint dengan JSON yang valid
cat > /var/www/html/health << 'EOF'
{
    "status": "healthy",
    "server": "azure-vpn",
    "region": "AZURE_REGION_PLACEHOLDER",
    "timestamp": TIMESTAMP_PLACEHOLDER,
    "services": {
        "shadowsocks": "8388",
        "http_proxy": "3128", 
        "health_check": "80"
    }
}
EOF

# Replace placeholders dengan dynamic values
sed -i "s/AZURE_REGION_PLACEHOLDER/$AZURE_REGION/g" /var/www/html/health
sed -i "s/TIMESTAMP_PLACEHOLDER/$(date +%s)/g" /var/www/html/health

# Test endpoints
echo ""
echo "🧪 Testing health endpoint:"
curl -s http://localhost/health | python3 -m json.tool

echo ""
echo "🧪 Testing IP endpoint:"
curl -s http://localhost/ip

echo ""
echo "📋 Getting connection details..."

# Get passwords dari config files
SHADOWSOCKS_PASSWORD=$(grep '"password"' /etc/shadowsocks/config.json | cut -d'"' -f4)
HTTP_PROXY_PASSWORD=$(grep vpnuser /etc/squid/passwd | cut -d':' -f2)

echo ""
echo "🎉 AZURE VPS CONNECTION DETAILS:"
echo "================================"
echo "Server IP: $SERVER_IP"
echo "Azure Region: $AZURE_REGION"
echo ""
echo "Shadowsocks:"
echo "  Host: $SERVER_IP"
echo "  Port: 8388"
echo "  Password: $SHADOWSOCKS_PASSWORD"
echo "  Method: aes-256-gcm"
echo ""
echo "HTTP Proxy:"
echo "  Host: $SERVER_IP"  
echo "  Port: 3128"
echo "  Username: vpnuser"
echo "  Password: [Check /etc/squid/passwd]"
echo ""
echo "Health Endpoints:"
echo "  Health: http://$SERVER_IP/health"
echo "  IP Check: http://$SERVER_IP/ip"
echo "  Speed Test: http://$SERVER_IP/speedtest"

# Create Chrome extension config
cat > /root/chrome-extension-config.txt << EOF
// Update background-azure.js dengan info ini:
const AZURE_VPS_CONFIG = {
    server: {
        name: 'Azure $AZURE_REGION',
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
        password: 'CHECK_SQUID_PASSWD'  // Check /etc/squid/passwd
    },
    health_endpoints: {
        health: 'http://$SERVER_IP/health',
        ip: 'http://$SERVER_IP/ip',
        speedtest: 'http://$SERVER_IP/speedtest'
    }
};
EOF

echo ""
echo "💾 Chrome extension config saved to: /root/chrome-extension-config.txt"
echo ""
echo "✅ Health endpoint fixed!"
echo "✅ Ready for Chrome extension integration!" 
