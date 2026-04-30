#!/bin/bash

SESSIONS_DIR="/var/cpanel/sessions"
RAW_DIR="$SESSIONS_DIR/raw"
PREAUTH_DIR="$SESSIONS_DIR/preauth"
ACCESS_LOG="/usr/local/cpanel/logs/access_log"

CRITICAL=0
ATTEMPTS=0
WARNINGS=0

echo "[*] Scanning cPanel session files..."
echo ""

if [ ! -d "$RAW_DIR" ]; then
    echo "[!] ERROR: Raw sessions directory not found: $RAW_DIR"
    exit 1
fi

for session_file in "$RAW_DIR"/*; do
    [ -f "$session_file" ] || continue

    session_name=$(basename "$session_file")
    preauth_file="$PREAUTH_DIR/$session_name"

    origin=$(grep -m1 '^origin_as_string=' "$session_file" | cut -d= -f2-)
    token_val=$(grep -m1 '^cp_security_token=' "$session_file" | cut -d= -f2-)
    denied_val=$(grep -m1 '^token_denied=' "$session_file" | cut -d= -f2-)
    external_auth=$(grep -m1 '^successful_external_auth_with_timestamp=' "$session_file")
    tfa_verified=$(grep -m1 '^tfa_verified=1' "$session_file")
    ip=$(echo "$origin" | sed -n 's/.*address=\([^,]*\).*/\1/p')
    app=$(echo "$origin" | sed -n 's/.*app=\([^,]*\).*/\1/p')
    method=$(echo "$origin" | sed -n 's/.*method=\([^,]*\).*/\1/p')

    # IOC 0: WHM badpass + cpsess + token_denied
    if [ -n "$denied_val" ] && [[ "$token_val" == /cpsess* ]] && [[ "$app" == "whostmgrd" ]] && [[ "$method" == "badpass" ]]; then

        used=""
        if [ -n "$token_val" ] && [ -f "$ACCESS_LOG" ]; then
            used=$(grep -a "$token_val" "$ACCESS_LOG" | grep -m1 " 200 ")
        fi

        if [ -n "$external_auth" ] || [ -n "$used" ]; then
            echo "[!] CRITICAL: Possible successful exploitation"
            echo "    - Session: $session_file"
            echo "    - IP: ${ip:-unknown}"
            echo "    - Token: $token_val"
            echo "    - token_denied: $denied_val"
            echo "    - Origin: $origin"
            [ -n "$external_auth" ] && echo "    - External auth marker: $external_auth"
            [ -n "$used" ] && echo "    - Token used with HTTP 200: $used"
            echo ""
            CRITICAL=1
        else
            echo "[*] ATTEMPT: WHM badpass token injection artifact, no sign of successful use"
            echo "    - Session: $session_file"
            echo "    - IP: ${ip:-unknown}"
            echo "    - Token: $token_val"
            echo "    - Origin: $origin"
            echo ""
            ATTEMPTS=$((ATTEMPTS+1))
        fi
    fi

    # IOC 1: Pre-auth session with external auth marker
    if [ -f "$preauth_file" ] && [ -n "$external_auth" ]; then
        echo "[!] CRITICAL: Pre-auth session contains successful external auth marker"
        echo "    - Session: $session_file"
        echo "    - Marker: $external_auth"
        echo "    - Origin: $origin"
        echo ""
        CRITICAL=1
    fi

    # IOC 2: tfa_verified with suspicious origin
    if [ -n "$tfa_verified" ] && \
       [[ "$method" != "handle_form_login" ]] && \
       [[ "$method" != "create_user_session" ]] && \
       [[ "$method" != "handle_auth_transfer" ]]; then
        echo "[!] WARNING: tfa_verified with unusual origin"
        echo "    - Session: $session_file"
        echo "    - Origin: $origin"
        echo ""
        WARNINGS=$((WARNINGS+1))
    fi

    # IOC 3: token_denied + cp_security_token but NOT WHM badpass
    # Usually expired token / normal user session / webmail noise
    if [ -n "$denied_val" ] && [ -n "$token_val" ] && ! { [[ "$app" == "whostmgrd" ]] && [[ "$method" == "badpass" ]]; }; then
        echo "[!] WARNING: token_denied + cp_security_token, but not WHM badpass"
        echo "    - Session: $session_file"
        echo "    - App: ${app:-unknown}"
        echo "    - Method: ${method:-unknown}"
        echo "    - IP: ${ip:-unknown}"
        echo "    - Origin: $origin"
        echo ""
        WARNINGS=$((WARNINGS+1))
    fi

done

echo "=============================="
echo "Scan summary"
echo "=============================="

if [ "$CRITICAL" -eq 1 ]; then
    echo "[!] CRITICAL indicators detected."
    echo ""
    echo "Recommended actions:"
    echo "  1. Preserve evidence:"
    echo "     cp -a /var/cpanel/sessions /root/ioc-sessions-\$(date +%F_%H%M%S)"
    echo "  2. Purge sessions:"
    echo "     find /var/cpanel/sessions/raw /var/cpanel/sessions/preauth -type f -delete && /scripts/restartsrv_cpsrvd"
    echo "  3. Force password reset for root and WHM users."
    echo "  4. Audit WHM/cPanel access logs and SSH logs."
    echo "  5. Check persistence: cron, SSH keys, systemd services, webshells."
    exit 2
fi

if [ "$ATTEMPTS" -gt 0 ]; then
    echo "[*] Exploitation attempts detected: $ATTEMPTS"
    echo "[*] No evidence of successful token use found."
    echo ""
    echo "Recommended actions:"
    echo "  1. Block listed IPs in CSF."
    echo "  2. Purge sessions:"
    echo "     find /var/cpanel/sessions/raw /var/cpanel/sessions/preauth -type f -delete && /scripts/restartsrv_cpsrvd"
    echo "  3. Ensure cPanel is updated:"
    echo "     /scripts/upcp --force"
    exit 1
fi

if [ "$WARNINGS" -gt 0 ]; then
    echo "[*] Warnings detected: $WARNINGS"
    echo "[*] These are usually expired tokens, webmail/cPanel noise, or normal sessions."
    echo "[+] No critical indicators of compromise found."
    exit 0
fi

echo "[+] No indicators of compromise found."
exit 0
