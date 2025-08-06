#!/bin/bash
set -e

### === CONFIG ===
ENV_FILE="/etc/cloudflare-bouncer/fastpanel-crowdsec-cloudflare.env"
ALLOWLIST_NAME="my_whitelists"
NOTIFY_SCRIPT="/etc/cloudflare-bouncer/notify-telegram.sh"
HOOK_SCRIPT="/etc/crowdsec/plugins/notification.sh"
INSTALL_SCRIPT_PATH="/etc/cloudflare-bouncer/install-full-stack.sh"
ACQUIS_FILE="/etc/crowdsec/acquis.yaml"
CLOUDFLARE_BOUNCER_CONFIG="/etc/crowdsec/bouncers/cs-cloudflare-bouncer.yaml"

### === FUNCȚII ===

log() { echo -e "🔹 $1"; }
notify() { bash "$NOTIFY_SCRIPT" "$1"; }

check_env_file() {
  if [ ! -f "$ENV_FILE" ]; then
    echo "⚠️  Fișierul $ENV_FILE nu există. Creează-l cu variabilele necesare."
    exit 1
  fi

  chmod 600 "$ENV_FILE"
  set -o allexport
  source "$ENV_FILE"
  set +o allexport

  REQUIRED_VARS=(CF_API_TOKEN CF_API_EMAIL CF_ACCOUNT_ID FASTPANEL_USER FASTPANEL_PASSWORD TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID TELEGRAM_THREAD_ID DASHBOARD_API_KEY)
  for VAR in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!VAR}" ]]; then
      echo "❌ Variabila $VAR nu este setată în $ENV_FILE"
      exit 1
    fi
  done
}

update_system() {
  log "Actualizez sistemul..."
  DEBIAN_FRONTEND=noninteractive apt-get update
  apt-get upgrade -y
  apt-get dist-upgrade -y
  apt-get autoremove -y
  apt-get install -y jq mc curl gnupg lsb-release
}

install_fastpanel() {
  log "Instalez FastPanel..."
  apt-get install -y ca-certificates wget
  wget https://repo.fastpanel.direct/install_fastpanel.sh -O - | bash -
  mogwai chpasswd -u "$FASTPANEL_USER" -p "$FASTPANEL_PASSWORD"
}

install_crowdsec() {
  log "Instalez CrowdSec și bouncerele..."
  curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
  apt install -y crowdsec crowdsec-firewall-bouncer-iptables crowdsec-cloudflare-bouncer
  systemctl enable --now crowdsec crowdsec-firewall-bouncer crowdsec-cloudflare-bouncer
}

install_collections() {
  log "Instalez colecții CrowdSec..."
  local collections=(
    crowdsecurity/base-http-scenarios openappsec/openappsec
    crowdsecurity/apache2 crowdsecurity/appsec-crs
    crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-wordpress
    crowdsecurity/postfix crowdsecurity/dovecot crowdsecurity/exim
    crowdsecurity/http-cve crowdsecurity/linux crowdsecurity/linux-lpe
    crowdsecurity/nginx crowdsecurity/http-dos crowdsecurity/sshd
    crowdsecurity/vsftpd crowdsecurity/wordpress crowdsecurity/mysql
    mstilkerich/bind9 crowdsecurity/proftpd crowdsecurity/whitelist-good-actors
  )

  for col in "${collections[@]}"; do
    cscli collections install "$col"
  done

  cscli scenarios install crowdsecurity/appsec-vpatch
  cscli scenarios install crowdsecurity/http-wordpress-scan
  cscli scenarios install crowdsecurity/http-wordpress_user-enum
  cscli scenarios install crowdsecurity/http-bf-wordpress_bf
  cscli scenarios install crowdsecurity/http-bf-wordpress_bf_xmlrpc
  cscli scenarios install crowdsecurity/http-wordpress_wpconfig
  cscli scenarios install crowdsecurity/nginx-req-limit-exceeded
  cscli scenarios install crowdsecurity/postfix-non-smtp-command
  cscli scenarios install crowdsecurity/postfix-spam
  cscli scenarios install crowdsecurity/postfix-relay-denied
  cscli scenarios install crowdsecurity/exim-spam
  cscli scenarios install crowdsecurity/exim-bf
  cscli scenarios install mstilkerich/bind9-refused
  cscli scenarios install crowdsecurity/proftpd-bf_user-enum
  cscli scenarios install crowdsecurity/proftpd-bf
  cscli scenarios install crowdsecurity/mysql-bf

  cscli parsers install crowdsecurity/iptables-logs
  cscli parsers install crowdsecurity/syslog-logs
  cscli parsers install crowdsecurity/nginx-logs

  cscli appsec-configs install crowdsecurity/appsec-default
  cscli appsec-configs install crowdsecurity/crs
  cscli appsec-configs install crowdsecurity/generic-rules
  cscli appsec-configs install crowdsecurity/virtual-patching

  cscli appsec-rules install crowdsecurity/base-config
  cscli appsec-rules install crowdsecurity/experimental-no-user-agent
  cscli appsec-rules install crowdsecurity/generic-freemarker-ssti
  cscli appsec-rules install crowdsecurity/crs
  cscli appsec-rules install crowdsecurity/generic-wordpress-uploads-listing
  cscli appsec-rules install crowdsecurity/generic-wordpress-uploads-php
  cscli appsec-rules install crowdsecurity/vpatch-env-access
  cscli appsec-rules install crowdsecurity/vpatch-git-config
  cscli appsec-rules install crowdsecurity/vpatch-symfony-profiler
}

configure_acquis() {
  log "Configurez acquis.yaml..."
  cp "$ACQUIS_FILE" "$ACQUIS_FILE.bak.$(date +%s)"

  cat > "$ACQUIS_FILE" <<EOF
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
labels:
  type: nginx-logs
---
filenames:
  - /var/www/*/data/logs/*-backend.access.log
  - /var/www/*/data/logs/*-frontend.access.log
  - /var/www/*/data/logs/*-backend.error.log
  - /var/www/*/data/logs/*-frontend.error.log
labels:
  type: nginx-logs
---
filenames:
  - /var/log/apache2/access.log
  - /var/log/apache2/error.log
  - /var/log/apache2/other_vhosts_access.log
labels:
  type: apache2
---
filenames:
  - /var/log/auth.log
  - /var/log/syslog
labels:
  type: syslog
EOF

  systemctl restart crowdsec
}

configure_cloudflare_bouncer() {
  log "Configurez Cloudflare bouncer..."
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
}

setup_allowlist() {
  log "Aplic whitelist la IP-uri..."

  cscli allowlist inspect "$ALLOWLIST_NAME" >/dev/null 2>&1 || \
    cscli allowlist create "$ALLOWLIST_NAME" -d "Webhook-uri, IP local și IP-uri personale"

  for ip in $WHITELIST_IPS; do
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] && \
      cscli allowlist add "$ALLOWLIST_NAME" "$ip" && echo "✅ Whitelisted: $ip"
  done

  SERVER_IP=$(curl -s https://ipinfo.io/ip)
  [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && \
    cscli allowlist add "$ALLOWLIST_NAME" "$SERVER_IP" && echo "✅ IP server adăugat în whitelist: $SERVER_IP"

  systemctl reload crowdsec
}

configure_telegram() {
  log "Configurez notificări Telegram..."
  mkdir -p /etc/cloudflare-bouncer

  cat > "$NOTIFY_SCRIPT" <<EOF
#!/bin/bash
MESSAGE=\$1
curl -s -X POST https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage \\
     -d chat_id=$TELEGRAM_CHAT_ID \\
     -d message_thread_id=$TELEGRAM_THREAD_ID \\
     -d text="\$MESSAGE"
EOF
  chmod +x "$NOTIFY_SCRIPT"
}

setup_hook() {
  log "Adaug hook pentru evenimente CrowdSec..."
  mkdir -p "$(dirname "$HOOK_SCRIPT")"
  cat > "$HOOK_SCRIPT" <<EOF
#!/bin/bash
ACTION=\$1
IP=\$2
REASON=\$3
MESSAGE="📡 CrowdSec: \$ACTION IP \$IP (Reason: \$REASON)"
$NOTIFY_SCRIPT "\$MESSAGE"
EOF
  chmod +x "$HOOK_SCRIPT"
}

connect_dashboard() {
  log "Conectez la CrowdSec Console..."
  cscli console enroll -e context "$DASHBOARD_API_KEY" || echo "❌ Conectarea a eșuat"
}

configure_crontab() {
  log "Configurez crontab..."
  (crontab -l 2>/dev/null | grep -q "update-cloudflare-bouncer.sh") || \
    (crontab -l 2>/dev/null; echo "0 */6 * * * /etc/cloudflare-bouncer/update-cloudflare-bouncer.sh >> /var/log/cloudflare-bouncer-update.log 2>&1") | crontab -
}

set_permissions() {
  log "Setez permisiuni scripturi..."
  chmod +x /etc/cloudflare-bouncer/install-full-stack.sh \
            /etc/cloudflare-bouncer/update-cloudflare-bouncer.sh
}

run_install_script_once() {
  [[ "$(realpath "$0")" != "$INSTALL_SCRIPT_PATH" ]] && bash "$INSTALL_SCRIPT_PATH"
}

### === EXECUȚIE ===

check_env_file
update_system
install_fastpanel
install_crowdsec
install_collections
configure_acquis
configure_cloudflare_bouncer
setup_allowlist
configure_telegram
setup_hook
connect_dashboard
configure_crontab
set_permissions

notify "✅ Instalare completă CrowdSec + FastPanel + Cloudflare + Telegram OK"
run_install_script_once

log "✅ Instalarea completă s-a finalizat."
