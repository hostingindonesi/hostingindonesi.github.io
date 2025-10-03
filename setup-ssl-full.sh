#!/bin/bash
# ==========================================
# Setup Lengkap Domain + SSL Internasional
# Domain: rupiahid-dompet.my.id
# ==========================================

DOMAIN="rupiahid-dompet.my.id"
EMAIL="admin@$DOMAIN"   # ganti dengan email aktif kamu

echo "🔧 Update & upgrade system..."
apt update -y && apt upgrade -y

echo "🌐 Install Nginx, Certbot, Firewall..."
apt install -y nginx certbot python3-certbot-nginx ufw

echo "🛡️ Konfigurasi firewall..."
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

echo "📂 Setup direktori web root..."
mkdir -p /var/www/$DOMAIN/html
echo "<h1>Website $DOMAIN sudah pakai SSL Internasional 🚀</h1>" > /var/www/$DOMAIN/html/index.html

echo "📝 Buat config Nginx untuk $DOMAIN..."
cat > /etc/nginx/sites-available/$DOMAIN <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;

    # Redirect semua HTTP ke HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;

    root /var/www/$DOMAIN/html;
    index index.html;

    # SSL Certifikat (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

ln -s /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/

echo "✅ Test konfigurasi Nginx..."
nginx -t && systemctl reload nginx

echo "🔐 Pasang SSL Let's Encrypt..."
certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos -m $EMAIL

echo "♻️ Aktifkan auto renew SSL..."
systemctl enable certbot.timer
systemctl start certbot.timer

echo "🚀 Selesai! Domain $DOMAIN sudah HTTPS Internasional dengan konfigurasi lengkap!"