#!/bin/bash

SESSIONS_DIR="/var/cpanel/sessions"
RAW_DIR="$SESSIONS_DIR/raw"
LOG_FILE="/var/log/auto_block_cpanel_ioc.log"
CSF_BIN="/usr/sbin/csf"
CSF_DENY="/etc/csf/csf.deny"

echo "[$(date '+%F %T')] Starting cPanel IOC scan..." >> "$LOG_FILE"

if [ ! -x "$CSF_BIN" ]; then
    echo "[$(date '+%F %T')] ERROR: CSF not found at $CSF_BIN" >> "$LOG_FILE"
    exit 1
fi

if [ ! -d "$RAW_DIR" ]; then
    echo "[$(date '+%F %T')] ERROR: cPanel raw sessions directory not found: $RAW_DIR" >> "$LOG_FILE"
    exit 1
fi

for session_file in "$RAW_DIR"/*; do
    [ -f "$session_file" ] || continue

    if grep -q '^token_denied=' "$session_file" && \
       grep -q '^cp_security_token=/cpsess' "$session_file" && \
       grep -q '^origin_as_string=.*app=whostmgrd' "$session_file" && \
       grep -q '^origin_as_string=.*method=badpass' "$session_file"; then

        IP=$(grep '^origin_as_string=' "$session_file" | sed -n 's/.*address=\([^,]*\).*/\1/p' | head -1)

        if [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            if [ -f "$CSF_DENY" ] && grep -qE "^$IP([ #]|$)" "$CSF_DENY"; then
                echo "[$(date '+%F %T')] Already blocked: $IP - $session_file" >> "$LOG_FILE"
            else
                "$CSF_BIN" -d "$IP" "Auto blocked: cPanel WHM badpass cpsess IOC"
                echo "[$(date '+%F %T')] BLOCKED: $IP - $session_file" >> "$LOG_FILE"
            fi
        else
            echo "[$(date '+%F %T')] Could not extract valid IP from $session_file" >> "$LOG_FILE"
        fi
    fi
done

echo "[$(date '+%F %T')] Scan finished." >> "$LOG_FILE"
