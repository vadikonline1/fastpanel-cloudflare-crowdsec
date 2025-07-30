#!/bin/bash

set -e

ENV_FILE="/etc/cloudflare-bouncer/fastpanel-crowdsec-cloudflare.env"
mkdir -p /etc/cloudflare-bouncer

# 1. Verificăm .env
if [ ! -f "$ENV_FILE" ]; then
  echo "⚠️  Fișierul $ENV_FILE nu există. Creează-l și definește variabilele:"
  echo "Exemplu: WHITELIST_IPS=\"1.2.3.4 5.6.7.0/24\""
  exit 1
fi

chmod 600 "$ENV_FILE"

# Încarcă variabilele
set -o allexport
source "$ENV_FILE"
set +o allexport

# 2. Verificăm variabile esențiale
REQUIRED_VARS=(CF_API_TOKEN CF_API_EMAIL CF_ACCOUNT_ID FASTPANEL_USER FASTPANEL_PASSWORD TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID TELEGRAM_THREAD_ID DASHBOARD_API_KEY)

for VAR in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!VAR}" ]]; then
    echo "❌ Variabila $VAR nu este setată în $ENV_FILE"
    exit 1
  fi
done

# 3. Update sistem
echo "🛠️  Update complet al sistemului..."
DEBIAN_FRONTEND=noninteractive apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y && apt-get autoremove -y && apt-get update && apt-get install -y jq && apt-get install -y mc

# 4. Repo CrowdSec
echo "➡️  Adaug repository-ul oficial CrowdSec..."
apt-get install -y curl gnupg lsb-release
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash

# 5. Instalează FastPanel
echo "📦 Instalez FastPanel..."
apt-get install -y ca-certificates wget
wget https://repo.fastpanel.direct/install_fastpanel.sh -O - | bash -

echo "🔑 Setez parola admin în FastPanel..."
mogwai chpasswd -u "$FASTPANEL_USER" -p "$FASTPANEL_PASSWORD"

# 6. Instalează CrowdSec + bouncere
echo "🛡️  Instalez CrowdSec și bouncerele..."
apt install -y crowdsec crowdsec-firewall-bouncer-iptables crowdsec-cloudflare-bouncer

systemctl enable --now crowdsec
systemctl enable --now crowdsec-firewall-bouncer
systemctl enable --now crowdsec-cloudflare-bouncer

# 7. Parsere și scenarii
echo "🔍 Instalez parsere/scenarii CrowdSec..."

# 📦 Colecții (collections)
cscli collections install crowdsecurity/apache2
cscli collections install crowdsecurity/appsec-crs
cscli collections install crowdsecurity/appsec-virtual-patching
cscli collections install crowdsecurity/appsec-wordpress
cscli collections install crowdsecurity/dovecot
cscli collections install crowdsecurity/exim
cscli collections install crowdsecurity/http-cve
cscli collections install crowdsecurity/linux
cscli collections install crowdsecurity/linux-lpe
cscli collections install crowdsecurity/nginx
cscli collections install crowdsecurity/sshd
cscli collections install crowdsecurity/vsftpd
cscli collections install crowdsecurity/wordpress
cscli collections install crowdsecurity/mysql
cscli collections install mstilkerich/bind9
cscli parsers install crowdsecurity/iptables-logs
cscli parsers install crowdsecurity/syslog-logs
cscli collections install crowdsecurity/proftpd

systemctl reload crowdsec


# 8. Config Cloudflare bouncer
echo "⚙️  Configurez bouncer Cloudflare..."
CLOUDFLARE_BOUNCER_CONFIG="/etc/crowdsec/bouncers/cs-cloudflare-bouncer.yaml"
mkdir -p /etc/crowdsec/bouncers
cat > "$CLOUDFLARE_BOUNCER_CONFIG" <<EOF
api_key: ""
api_token: "$CF_API_TOKEN"
api_email: "$CF_API_EMAIL"
account_id: "$CF_ACCOUNT_ID"
zone_ids: []
custom_ip_categories:
  - crowdsec-blocklist
default_action: challenge
ip_cache_size: 5000
log_level: info
update_frequency: 10m
EOF

systemctl restart crowdsec-cloudflare-bouncer

# 9. Whitelist IP-uri
echo "🔐 Aplic whitelist la IP-uri/subrețele..."
WHITELIST_FILE="/etc/crowdsec/config/whitelists.yaml"
cat > "$WHITELIST_FILE" <<EOF
whitelists:
  - reason: "Webhook-uri, IP local și IP-uri personale"
    ip:
EOF

for ip in $WHITELIST_IPS; do
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
    echo "    - \"$ip\"" >> "$WHITELIST_FILE"
    echo "✅ Whitelisted: $ip"
  else
    echo "❌ IP invalid ignorat: $ip"
  fi
done

# IP public server
SERVER_IP=$(curl -s https://ipinfo.io/ip)
if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "    - \"$SERVER_IP\"" >> "$WHITELIST_FILE"
  echo "✅ IP server adăugat în whitelist: $SERVER_IP"
fi

systemctl reload crowdsec

# 10. Notificări Telegram
echo "📩 Configurez notificări Telegram..."
NOTIFY_SCRIPT="/etc/cloudflare-bouncer/notify-telegram.sh"
cat > "$NOTIFY_SCRIPT" <<EOF
#!/bin/bash
MESSAGE=\$1
curl -s -X POST https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage \\
     -d chat_id=$TELEGRAM_CHAT_ID \\
     -d message_thread_id=$TELEGRAM_THREAD_ID \\
     -d text="\$MESSAGE"
EOF

chmod +x "$NOTIFY_SCRIPT"

# Mesaj de test
"$NOTIFY_SCRIPT" "✅ Instalare completă CrowdSec + FastPanel + Cloudflare + Telegram OK"

# 11. Hook evenimente
HOOK_SCRIPT="/etc/crowdsec/plugins/notification.sh"
mkdir -p /etc/crowdsec/plugins
cat > "$HOOK_SCRIPT" <<EOF
#!/bin/bash
ACTION=\$1
IP=\$2
REASON=\$3
MESSAGE="📡 CrowdSec: \$ACTION IP \$IP (Reason: \$REASON)"
$NOTIFY_SCRIPT "\$MESSAGE"
EOF

chmod +x "$HOOK_SCRIPT"

# 12. Conectare la CrowdSec Console (Dashboard API)
echo "🌐 Conectez la CrowdSec Console via API..."
cscli console enroll -e context "$DASHBOARD_API_KEY" || echo "❌ Conectarea la dashboard a eșuat"

# 13. Permisiuni scripturi
echo "🛠️  Setez permisiuni pentru scripturi..."
chmod +x /etc/cloudflare-bouncer/sync-env.sh
chmod +x /etc/cloudflare-bouncer/install-full-stack.sh
chmod +x /etc/cloudflare-bouncer/update-cloudflare-bouncer.sh

# 14. Adaugă în crontab
echo "📅 Adaug joburi în crontab..."
(crontab -l 2>/dev/null; echo "0 */6 * * * /etc/cloudflare-bouncer/update-cloudflare-bouncer.sh >> /var/log/cloudflare-bouncer-update.log 2>&1") | crontab -
(crontab -l 2>/dev/null; echo "*/30 * * * * /etc/cloudflare-bouncer/sync-env.sh >> /var/log/cloudflare-sync.log 2>&1") | crontab -

# 15. Rulează instalare finală
echo "🚀 Execut scriptul curent pentru a finaliza procesul...
/etc/cloudflare-bouncer/install-full-stack.sh"

