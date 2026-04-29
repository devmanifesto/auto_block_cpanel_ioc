#!/usr/bin/env bash
#
# auto_block_cpanel_ioc.sh
#
# Detecta IOCs de explotacion pre-auth contra WHM (CVE-2026-41940 y similares)
# en /var/cpanel/sessions/raw/ y bloquea las IPs origen via CSF.
#
# NOTA: Este script es una capa de respuesta complementaria. La mitigacion
# principal de CVE-2026-41940 es actualizar cPanel/WHM a la version parcheada
# (ver README.md). No reemplaza el parcheo.
#
# Uso:
#   bash auto_block_cpanel_ioc.sh [--dry-run] [--debug]
#
# Variables de entorno opcionales:
#   AUTO_BLOCK_DRY_RUN=1    No ejecuta csf -d, solo loguea (equivalente a --dry-run)
#   AUTO_BLOCK_DEBUG=1      Verbose en stderr

set -Eeuo pipefail
shopt -s nullglob

# ----------------------------------------------------------------------------
# Sanity checks de entorno
# ----------------------------------------------------------------------------

if [ -z "${BASH_VERSION:-}" ]; then
    echo "ERROR: este script requiere bash, no POSIX sh." >&2
    exit 2
fi

# ----------------------------------------------------------------------------
# Configuracion
# ----------------------------------------------------------------------------

SESSIONS_DIR="${AUTO_BLOCK_SESSIONS_DIR:-/var/cpanel/sessions}"
RAW_DIR="${AUTO_BLOCK_RAW_DIR:-$SESSIONS_DIR/raw}"
LOG_FILE="${AUTO_BLOCK_LOG_FILE:-/var/log/auto_block_cpanel_ioc.log}"
CSF_BIN="${AUTO_BLOCK_CSF_BIN:-/usr/sbin/csf}"
CSF_DENY="${AUTO_BLOCK_CSF_DENY:-/etc/csf/csf.deny}"
LOCK_FILE="${AUTO_BLOCK_LOCK_FILE:-/var/run/auto_block_cpanel_ioc.lock}"
BLOCK_COMMENT="${AUTO_BLOCK_COMMENT:-Auto blocked: cPanel WHM badpass cpsess IOC (CVE-2026-41940 pattern)}"

DRY_RUN="${AUTO_BLOCK_DRY_RUN:-0}"
DEBUG="${AUTO_BLOCK_DEBUG:-0}"

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --debug)   DEBUG=1 ;;
        -h|--help)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: argumento desconocido: $1" >&2
            exit 2
            ;;
    esac
    shift
done

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "ERROR: este script debe ejecutarse como root." >&2
    exit 2
fi

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------

log() {
    local level="$1"; shift
    local ts
    ts="$(date '+%F %T')"
    printf '[%s] [%s] [pid=%d] %s\n' "$ts" "$level" "$$" "$*" >> "$LOG_FILE"
    if [ "$DEBUG" = "1" ]; then
        printf '[%s] [%s] %s\n' "$ts" "$level" "$*" >&2
    fi
}

on_error() {
    local exit_code=$?
    local line_no=${1:-?}
    log ERROR "Fallo inesperado (exit=$exit_code) en linea $line_no"
    exit "$exit_code"
}
trap 'on_error $LINENO' ERR

if ! { : >> "$LOG_FILE"; } 2>/dev/null; then
    echo "ERROR: no se puede escribir en $LOG_FILE" >&2
    exit 2
fi
chmod 600 "$LOG_FILE" 2>/dev/null || true

# ----------------------------------------------------------------------------
# Lock para evitar ejecuciones concurrentes
# ----------------------------------------------------------------------------

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log INFO "Otra instancia en ejecucion (lock=$LOCK_FILE), saliendo."
    exit 0
fi

log INFO "Iniciando escaneo IOC cPanel (dry_run=$DRY_RUN)"

# ----------------------------------------------------------------------------
# Validaciones previas
# ----------------------------------------------------------------------------

if [ ! -x "$CSF_BIN" ]; then
    log ERROR "CSF no encontrado o sin permisos de ejecucion: $CSF_BIN"
    exit 1
fi

if [ ! -d "$RAW_DIR" ]; then
    log ERROR "Directorio de sesiones raw no encontrado: $RAW_DIR"
    exit 1
fi

if [ ! -r "$RAW_DIR" ]; then
    log ERROR "Sin permisos de lectura sobre: $RAW_DIR"
    exit 1
fi

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

# Valida IPv4 con octetos 0-255
is_valid_ipv4() {
    local ip="$1"
    local IFS='.'
    # shellcheck disable=SC2206
    local parts=($ip)
    [ "${#parts[@]}" -eq 4 ] || return 1
    local octet
    for octet in "${parts[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        # Sin ceros a la izquierda (excepto el propio "0")
        if [ "${#octet}" -gt 1 ] && [ "${octet:0:1}" = "0" ]; then
            return 1
        fi
        if [ "$octet" -gt 255 ]; then
            return 1
        fi
    done
    # Descarta loopback / 0.0.0.0 / broadcast tipico
    case "$ip" in
        0.0.0.0|255.255.255.255|127.0.0.1) return 1 ;;
    esac
    return 0
}

# Comprueba si una IP ya esta en csf.deny (comparacion literal de la IP)
is_already_denied() {
    local ip="$1"
    [ -r "$CSF_DENY" ] || return 1
    # Escapa los puntos para usar regex segura
    local ip_escaped="${ip//./\\.}"
    grep -qE "^[[:space:]]*${ip_escaped}([[:space:]]|#|$)" "$CSF_DENY"
}

# Extrae la IP del campo address= en origin_as_string=
# Estructura tipica: origin_as_string=...,address=1.2.3.4,...
extract_ip_from_session() {
    local file="$1"
    # Toma el ultimo origin_as_string (suele ser el evento mas reciente)
    local line
    line="$(grep -E '^origin_as_string=' -- "$file" | tail -n 1 || true)"
    [ -n "$line" ] || return 1
    local ip
    ip="$(printf '%s' "$line" | sed -n 's/.*address=\([0-9.]\{1,15\}\).*/\1/p' | head -n 1 || true)"
    [ -n "$ip" ] || return 1
    printf '%s' "$ip"
}

# Devuelve 0 si el archivo cumple TODO el IOC
matches_ioc() {
    local file="$1"
    grep -q '^token_denied=' -- "$file" || return 1
    grep -q '^cp_security_token=/cpsess' -- "$file" || return 1
    # Mismo origin_as_string debe contener app=whostmgrd Y method=badpass
    grep -Eq '^origin_as_string=.*\bapp=whostmgrd\b.*\bmethod=badpass\b|^origin_as_string=.*\bmethod=badpass\b.*\bapp=whostmgrd\b' -- "$file" || return 1
    return 0
}

# block_ip codigo de retorno:
#   0 = bloqueo efectivo (csf -d ejecutado OK o dry-run)
#   2 = ya estaba bloqueado en csf.deny
#   1 = csf -d fallo
block_ip() {
    local ip="$1"
    local source_file="$2"

    if is_already_denied "$ip"; then
        log INFO "Already blocked: $ip (src=$source_file)"
        return 2
    fi

    if [ "$DRY_RUN" = "1" ]; then
        log INFO "DRY-RUN would block: $ip (src=$source_file)"
        return 0
    fi

    local csf_output csf_rc=0
    csf_output="$("$CSF_BIN" -d "$ip" "$BLOCK_COMMENT" 2>&1)" || csf_rc=$?

    if [ "$csf_rc" -eq 0 ]; then
        log INFO "BLOCKED: $ip (src=$source_file)"
        return 0
    fi

    local csf_summary
    csf_summary="$(printf '%s' "$csf_output" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
    log ERROR "BLOCK FAILED: $ip rc=$csf_rc src=$source_file csf_output='${csf_summary:0:500}'"
    return 1
}

# ----------------------------------------------------------------------------
# Escaneo principal
# ----------------------------------------------------------------------------

scanned=0
matched=0
blocked=0
already=0
failed=0
skipped_invalid=0

for session_file in "$RAW_DIR"/*; do
    [ -f "$session_file" ] || continue
    [ -r "$session_file" ] || { log WARN "Sin lectura: $session_file"; continue; }

    scanned=$((scanned + 1))

    if ! matches_ioc "$session_file"; then
        continue
    fi
    matched=$((matched + 1))

    ip="$(extract_ip_from_session "$session_file" || true)"

    if [ -z "${ip:-}" ]; then
        log WARN "IOC detectado pero IP no extraible: $session_file"
        skipped_invalid=$((skipped_invalid + 1))
        continue
    fi

    if ! is_valid_ipv4 "$ip"; then
        log WARN "IOC detectado con IP invalida ($ip): $session_file"
        skipped_invalid=$((skipped_invalid + 1))
        continue
    fi

    rc=0
    block_ip "$ip" "$session_file" || rc=$?
    case "$rc" in
        0) blocked=$((blocked + 1)) ;;
        2) already=$((already + 1)) ;;
        *) failed=$((failed + 1)) ;;
    esac
done

log INFO "Scan finalizado: scanned=$scanned matched=$matched blocked=$blocked already=$already failed=$failed skipped_invalid=$skipped_invalid dry_run=$DRY_RUN"
exit 0
