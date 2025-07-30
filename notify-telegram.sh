#!/bin/bash

# Încarcă variabilele din fișierul .env
source /etc/cloudflare-bouncer/fastpanel-crowdsec-cloudflare.env

MESSAGE="$1"

curl -s -X POST https://api.telegram.org/bot"$TELEGRAM_BOT_TOKEN"/sendMessage \
     -d chat_id="$TELEGRAM_CHAT_ID" \
     -d message_thread_id="$TELEGRAM_THREAD_ID" \
     -d text="$MESSAGE"
