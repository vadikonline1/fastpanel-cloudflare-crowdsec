#!/bin/bash

set -e

# === 1. Load environment ===
ENV_FILE="/etc/cloudflare-bouncer/fastpanel-crowdsec-cloudflare.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "⚠️ Fișierul $ENV_FILE nu există. Oprire."
  exit 1
fi

source "$ENV_FILE"

# === 2. Validări variabile esențiale ===
REQUIRED_VARS=(CF_API_TOKEN CF_API_EMAIL CF_ACCOUNT_ID TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID TELEGRAM_THREAD_ID CROWDSEC_LAPI_KEY)
for VAR in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!VAR}" ]]; then
    echo "❌ Variabila $VAR nu este setată în $ENV_FILE"
    exit 1
  fi
done

# === 3. Set config paths ===
CONFIG_FILE="/etc/crowdsec/bouncers/cs-cloudflare-bouncer.yaml"
TMP_CONFIG="/tmp/cs-cloudflare-bouncer.new.yaml"
TMP_ZONES="/tmp/cf_zones.json"
LOG_FILE="/var/log/cloudflare-bouncer-update.log"

# === 4. Obține lista de zone din Cloudflare ===
curl -s -X GET "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" > "$TMP_ZONES"

ZONES=$(jq -r '.result[] | "\(.name):\(.id)"' "$TMP_ZONES")
if [[ -z "$ZONES" ]]; then
  echo "[!] ❌ Nu s-au găsit zone Cloudflare!" | tee -a "$LOG_FILE"
  curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
    -d chat_id="$TELEGRAM_CHAT_ID" \
    -d message_thread_id="$TELEGRAM_THREAD_ID" \
    -d text="❌ CrowdSec Cloudflare Bouncer: Nu s-au găsit zone în contul Cloudflare!"
  exit 1
fi

# === 5. Construiește lista zone_ids ===
ZONE_IDS=$(echo "$ZONES" | awk -F ':' '{print "  - \"" $2 "\"" }')

# === 6. Construiește whitelist IPs ===
WHITELIST_BLOCK=""
IFS=' ' read -r -a IPS <<< "$WHITELIST_IPS"
for ip in "${IPS[@]}"; do
  WHITELIST_BLOCK+="  - $ip"$'\n'
done

# === 7. Generează noul config temporar ===
cat > "$TMP_CONFIG" <<EOF
crowdsec_lapi_url: "http://127.0.0.1:8080"
lapi_key: "$CROWDSEC_LAPI_KEY"
api_token: "$CF_API_TOKEN"
api_email: "$CF_API_EMAIL"
account_id: "$CF_ACCOUNT_ID"
zone_ids:
$ZONE_IDS
custom_ip_categories:
  - crowdsec-blocklist
default_action: challenge
ip_cache_size: 5000
log_level: info
update_frequency: 10m
whitelisted_ips:
$WHITELIST_BLOCK
EOF

# === 8. Compară și aplică modificări doar dacă e diferit ===
if cmp -s "$TMP_CONFIG" "$CONFIG_FILE"; then
  echo "[=] Nicio modificare. Configul este deja actualizat." | tee -a "$LOG_FILE"
else
  mv "$TMP_CONFIG" "$CONFIG_FILE"
  echo "[+] Config actualizat. Restart crowdsec-cloudflare-bouncer..." | tee -a "$LOG_FILE"
  systemctl restart crowdsec-cloudflare-bouncer

  # Notificare Telegram
  curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
    -d chat_id="$TELEGRAM_CHAT_ID" \
    -d message_thread_id="$TELEGRAM_THREAD_ID" \
    -d text="✅ Config bouncer Cloudflare actualizat. Domenii: $(echo "$ZONES" | wc -l)"
fi

# === 9. Afișare în consolă ===
echo "✅ Domenii actualizate:"
echo "$ZONES"