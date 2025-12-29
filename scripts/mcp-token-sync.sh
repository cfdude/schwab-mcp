#!/bin/bash
#
# MCP Token Sync Script
#
# Keeps MCP OAuth tokens synchronized across mcp-remote versions.
# When upgrading mcp-remote (e.g., 0.1.35 -> 0.1.36), tokens are stored
# in versioned directories. This script copies tokens to the current version.
#
# Also handles refreshing tokens when they're stale by triggering a brief
# connection to the MCP server.
#
# Usage: ./mcp-token-sync.sh
# Run at login or via launchd to ensure smooth reconnection.

set -euo pipefail

# Configuration
MCP_AUTH_DIR="$HOME/.mcp-auth"
SCHWAB_URL="https://schwab-mcp-rsherman.onvex.workers.dev/sse"
SCHWAB_URL_HASH="cee935839bfcb46a76e0f0d7c68d5afa"  # md5 of SCHWAB_URL
CURRENT_VERSION="0.1.36"  # Update this when upgrading mcp-remote
LOG_FILE="$HOME/Library/Logs/trading/mcp-token-sync.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    echo "[$level] $message"
}

# Find the latest version directory with tokens for Schwab
find_latest_tokens() {
    local latest_version=""
    local latest_time=0

    for dir in "$MCP_AUTH_DIR"/mcp-remote-*/; do
        local tokens_file="${dir}${SCHWAB_URL_HASH}_tokens.json"
        if [[ -f "$tokens_file" ]]; then
            local mod_time=$(stat -f %m "$tokens_file" 2>/dev/null || echo 0)
            if [[ "$mod_time" -gt "$latest_time" ]]; then
                latest_time="$mod_time"
                latest_version="$dir"
            fi
        fi
    done

    echo "$latest_version"
}

# Sync tokens from source version to current version
sync_tokens() {
    local source_dir="$1"
    local target_dir="$MCP_AUTH_DIR/mcp-remote-$CURRENT_VERSION"

    # Create target directory if needed
    mkdir -p "$target_dir"

    # Copy all Schwab-related files
    local copied=0
    for suffix in "_tokens.json" "_client_info.json" "_code_verifier.txt" "_lock.json"; do
        local source_file="${source_dir}${SCHWAB_URL_HASH}${suffix}"
        local target_file="${target_dir}/${SCHWAB_URL_HASH}${suffix}"

        if [[ -f "$source_file" ]]; then
            # Only copy if source is newer or target doesn't exist
            if [[ ! -f "$target_file" ]] || [[ "$source_file" -nt "$target_file" ]]; then
                cp "$source_file" "$target_file"
                ((copied++))
            fi
        fi
    done

    echo "$copied"
}

# Check if tokens exist for current version
check_current_tokens() {
    local target_dir="$MCP_AUTH_DIR/mcp-remote-$CURRENT_VERSION"
    local tokens_file="${target_dir}/${SCHWAB_URL_HASH}_tokens.json"

    if [[ -f "$tokens_file" ]]; then
        echo "exists"
    else
        echo "missing"
    fi
}

# Main logic
main() {
    log "INFO" "Starting MCP token sync..."

    # Check if current version has tokens
    local current_status=$(check_current_tokens)

    if [[ "$current_status" == "exists" ]]; then
        log "INFO" "Tokens already exist for mcp-remote-$CURRENT_VERSION"

        # Check token age and refresh if stale (older than 1 hour)
        local tokens_file="$MCP_AUTH_DIR/mcp-remote-$CURRENT_VERSION/${SCHWAB_URL_HASH}_tokens.json"
        local age_seconds=$(($(date +%s) - $(stat -f %m "$tokens_file")))

        if [[ "$age_seconds" -gt 3600 ]]; then
            log "INFO" "Tokens are ${age_seconds}s old, triggering refresh..."
            # Brief connection to refresh tokens
            timeout 15 npx mcp-remote@$CURRENT_VERSION "$SCHWAB_URL" > /dev/null 2>&1 || true
            log "SUCCESS" "Token refresh completed"
        else
            log "INFO" "Tokens are fresh (${age_seconds}s old)"
        fi

        return 0
    fi

    log "WARN" "No tokens found for mcp-remote-$CURRENT_VERSION"

    # Find latest tokens from any version
    local source_dir=$(find_latest_tokens)

    if [[ -z "$source_dir" ]]; then
        log "WARN" "No Schwab tokens found in any version. Manual auth required."
        return 1
    fi

    log "INFO" "Found tokens in: $source_dir"

    # Sync tokens
    local copied=$(sync_tokens "$source_dir")

    if [[ "$copied" -gt 0 ]]; then
        log "SUCCESS" "Synced $copied token files from $source_dir to mcp-remote-$CURRENT_VERSION"
    else
        log "INFO" "No new files to sync"
    fi

    log "INFO" "Token sync completed"
}

main "$@"
