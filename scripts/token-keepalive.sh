#!/bin/bash
#
# Schwab Token Keep-Alive Script
#
# Keeps Schwab OAuth tokens fresh by making periodic API calls.
# Run via cron to prevent token expiration.
#
# Usage: ./token-keepalive.sh
# Cron:  0 8,20 * * * /Users/robsherman/Servers/schwab-mcp/scripts/token-keepalive.sh
#

set -euo pipefail

# Configuration
API_URL="https://schwab-mcp-rsherman.onvex.workers.dev"
API_KEY="${SCHWAB_API_KEY:-YQptbYy5bweAafDh4T9wXNxqNsZ18m3JJV5mAtX1XulGHXlBVfN1l2PKBIKFS4xz}"
LOG_FILE="${HOME}/schwab-keepalive.log"
ALERT_THRESHOLD_HOURS=48  # Alert if tokens expire within this many hours
LOG_ROTATION_DAYS=30      # Rotate log after this many days
LOG_RETENTION_COUNT=3     # Keep this many old log files

# Colors for terminal output (disabled in cron)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"

    case "$level" in
        "ERROR")   echo -e "${RED}[$level]${NC} $message" ;;
        "WARN")    echo -e "${YELLOW}[$level]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[$level]${NC} $message" ;;
        *)         echo "[$level] $message" ;;
    esac
}

# Check token status
check_status() {
    local response
    response=$(curl -s -H "Authorization: Bearer $API_KEY" "$API_URL/api/status" 2>&1)

    if [[ -z "$response" ]]; then
        log "ERROR" "Failed to connect to API"
        return 1
    fi

    echo "$response"
}

# Make an API call to trigger token refresh
refresh_tokens() {
    local response
    response=$(curl -s -H "Authorization: Bearer $API_KEY" "$API_URL/api/accounts" 2>&1)

    if echo "$response" | jq -e 'if type == "array" then true else false end' > /dev/null 2>&1; then
        return 0
    else
        local error=$(echo "$response" | jq -r '.error // "Unknown error"' 2>/dev/null || echo "Parse error")
        log "ERROR" "API call failed: $error"
        return 1
    fi
}

# Send desktop notification (macOS)
notify() {
    local title="$1"
    local message="$2"

    if command -v osascript &> /dev/null; then
        osascript -e "display notification \"$message\" with title \"$title\"" 2>/dev/null || true
    fi
}

# Rotate log file if older than LOG_ROTATION_DAYS
rotate_log() {
    # Skip if log file doesn't exist
    [[ -f "$LOG_FILE" ]] || return 0

    # Get file age in days (macOS compatible)
    local file_mod_time
    if [[ "$(uname)" == "Darwin" ]]; then
        file_mod_time=$(stat -f %m "$LOG_FILE")
    else
        file_mod_time=$(stat -c %Y "$LOG_FILE")
    fi

    local current_time=$(date +%s)
    local age_days=$(( (current_time - file_mod_time) / 86400 ))

    if [[ $age_days -ge $LOG_ROTATION_DAYS ]]; then
        local timestamp=$(date +%Y%m%d)
        local rotated_file="${LOG_FILE}.${timestamp}"

        # Rotate current log
        mv "$LOG_FILE" "$rotated_file"
        touch "$LOG_FILE"

        log "INFO" "Log rotated: $rotated_file (was $age_days days old)"

        # Clean up old rotated logs, keep only LOG_RETENTION_COUNT most recent
        local log_dir=$(dirname "$LOG_FILE")
        local log_base=$(basename "$LOG_FILE")

        # Find and delete old rotated logs beyond retention count
        ls -t "${LOG_FILE}".* 2>/dev/null | tail -n +$((LOG_RETENTION_COUNT + 1)) | while read old_log; do
            rm -f "$old_log"
            log "INFO" "Deleted old log: $old_log"
        done
    fi
}

# Main logic
main() {
    # Rotate log if needed (before logging anything new)
    rotate_log

    log "INFO" "Starting Schwab token keep-alive check..."

    # Get current status
    local status_response
    status_response=$(check_status)

    if [[ $? -ne 0 ]]; then
        log "ERROR" "Could not get token status"
        notify "Schwab Token Alert" "Failed to check token status"
        exit 1
    fi

    local status=$(echo "$status_response" | jq -r '.status // "unknown"')
    local expires_in=$(echo "$status_response" | jq -r '.expiresInSeconds // 0')
    local has_refresh=$(echo "$status_response" | jq -r '.hasRefreshToken // false')
    local expires_at=$(echo "$status_response" | jq -r '.expiresAt // "unknown"')

    log "INFO" "Current status: $status, expires_in: ${expires_in}s, has_refresh: $has_refresh"

    # Check if we need to alert about expiring tokens
    local alert_threshold_seconds=$((ALERT_THRESHOLD_HOURS * 3600))

    case "$status" in
        "valid")
            # Make an API call to ensure tokens stay fresh
            if refresh_tokens; then
                log "SUCCESS" "Token refresh successful. Tokens valid until $expires_at"

                # Check if approaching expiration
                if [[ "$expires_in" -lt "$alert_threshold_seconds" ]]; then
                    local hours_left=$((expires_in / 3600))
                    log "WARN" "Tokens expire in $hours_left hours - consider re-authenticating soon"
                    notify "Schwab Token Warning" "Tokens expire in $hours_left hours"
                fi
            else
                log "ERROR" "Token refresh failed"
                notify "Schwab Token Alert" "Token refresh failed - check logs"
                exit 1
            fi
            ;;

        "expired")
            log "WARN" "Access token expired, attempting refresh..."

            if [[ "$has_refresh" == "true" ]]; then
                if refresh_tokens; then
                    log "SUCCESS" "Successfully refreshed expired tokens"
                    notify "Schwab Tokens" "Expired tokens successfully refreshed"
                else
                    log "ERROR" "Failed to refresh expired tokens"
                    notify "Schwab Token Alert" "Re-authentication required"
                    exit 1
                fi
            else
                log "ERROR" "No refresh token available - manual re-auth required"
                notify "Schwab Token Alert" "Manual re-authentication required"
                exit 1
            fi
            ;;

        "no_tokens")
            log "ERROR" "No tokens found - manual authentication required"
            notify "Schwab Token Alert" "No tokens - authenticate via Claude Desktop"
            exit 1
            ;;

        *)
            log "WARN" "Unknown status: $status"
            ;;
    esac

    log "INFO" "Keep-alive check completed successfully"
}

# Run main function
main "$@"
