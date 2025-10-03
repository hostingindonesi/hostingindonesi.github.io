#!/bin/bash
# ==========================================
# Setup SSL Internasional (Let's Encrypt) 
# untuk domain: rupiahid-dompet.my.id
# ==========================================

DOMAIN="rupiahid-dompet.my.id"
EMAIL="admin@$DOMAIN"  # ganti dengan email aktif

echo "🔧 Update system..."
apt update -y && apt upgrade -y

echo "🌐 Install Nginx + Certbot..."
apt install -y nginx certbot python3-certbot-nginx ufw

echo "🛡️ Config firewall..."
ufw allow 'Nginx Full'
ufw reload

echo "📂 Setup web root..."
mkdir -p /var/www/$DOMAIN/html
echo "<h1>Selamat datang di $DOMAIN dengan SSL Internasional!</h1>" > /var/www/$DOMAIN/html/index.html

echo "📝 Buat config Nginx..."
cat > /etc/nginx/sites-available/$DOMAIN <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;

    root /var/www/$DOMAIN/html;
    index index.html;

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

echo "♻️ Aktifkan auto-renew SSL..."
systemctl enable certbot.timer
systemctl start certbot.timer

echo "🚀 Selesai! Domain $DOMAIN sudah HTTPS Internasional!"