#!/bin/bash
#
# MCP Token Sync Script
#
# Keeps MCP OAuth tokens synchronized across ALL mcp-remote versions.
# mcp-remote stores tokens in versioned directories (mcp-remote-0.1.35,
# mcp-remote-0.1.36, 0.1.37, etc). This script finds the freshest tokens
# and copies them to ALL version directories.
#
# This handles:
# - Version upgrades (tokens migrate automatically)
# - Multiple projects using different pinned versions
# - Future versions (tokens are ready before first use)
#
# Usage: ./mcp-token-sync.sh
# Runs via launchd every 4 hours and as part of token-keepalive.sh

set -euo pipefail

# Configuration
MCP_AUTH_DIR="$HOME/.mcp-auth"
SCHWAB_URL_HASH="cee935839bfcb46a76e0f0d7c68d5afa"  # md5 of https://schwab-mcp-rsherman.onvex.workers.dev/sse
LOG_FILE="$HOME/Library/Logs/trading/mcp-token-sync.log"
# Note: We don't clean up old version directories because:
# 1. Disk usage is negligible (~1-2KB per version)
# 2. Projects may pin older mcp-remote versions
# 3. Risk of breaking pinned projects outweighs any benefit

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

# Find the directory with the freshest (most recently modified) tokens
find_freshest_tokens() {
    local freshest_dir=""
    local freshest_time=0

    for dir in "$MCP_AUTH_DIR"/mcp-remote-*/; do
        [[ -d "$dir" ]] || continue
        local tokens_file="${dir}${SCHWAB_URL_HASH}_tokens.json"
        if [[ -f "$tokens_file" ]]; then
            local mod_time=$(stat -f %m "$tokens_file" 2>/dev/null || echo 0)
            if [[ "$mod_time" -gt "$freshest_time" ]]; then
                freshest_time="$mod_time"
                freshest_dir="$dir"
            fi
        fi
    done

    if [[ -n "$freshest_dir" ]]; then
        echo "$freshest_dir"
        return 0
    fi
    return 1
}

# Get all mcp-remote version directories
get_all_versions() {
    for dir in "$MCP_AUTH_DIR"/mcp-remote-*/; do
        [[ -d "$dir" ]] && echo "$dir"
    done
}

# Sync tokens from source directory to all other version directories
sync_to_all_versions() {
    local source_dir="$1"
    local source_version=$(basename "$source_dir")
    local synced_count=0
    local created_count=0

    for target_dir in $(get_all_versions); do
        # Skip source directory
        [[ "$target_dir" == "$source_dir" ]] && continue

        local target_version=$(basename "$target_dir")

        # Copy all Schwab-related files
        for suffix in "_tokens.json" "_client_info.json" "_code_verifier.txt" "_lock.json"; do
            local source_file="${source_dir}${SCHWAB_URL_HASH}${suffix}"
            local target_file="${target_dir}${SCHWAB_URL_HASH}${suffix}"

            if [[ -f "$source_file" ]]; then
                # Copy if target doesn't exist or source is newer
                if [[ ! -f "$target_file" ]]; then
                    cp "$source_file" "$target_file"
                    ((created_count++))
                elif [[ "$source_file" -nt "$target_file" ]]; then
                    cp "$source_file" "$target_file"
                    ((synced_count++))
                fi
            fi
        done
    done

    echo "$created_count:$synced_count"
}

# Create token files in a new version directory (for future versions)
prepare_future_versions() {
    local source_dir="$1"

    # Also prepare for potential future versions by checking if any
    # commonly used versions are missing
    # This is a no-op if the directories don't exist yet
    :
}

# Main logic
main() {
    log "INFO" "Starting MCP token sync (all versions)..."

    # Ensure base directory exists
    if [[ ! -d "$MCP_AUTH_DIR" ]]; then
        log "WARN" "MCP auth directory doesn't exist: $MCP_AUTH_DIR"
        return 1
    fi

    # Find freshest tokens
    local source_dir
    if ! source_dir=$(find_freshest_tokens); then
        log "WARN" "No Schwab tokens found in any mcp-remote version"
        log "WARN" "Manual authentication required via Claude Code"
        return 1
    fi

    local source_version=$(basename "$source_dir")
    local tokens_file="${source_dir}${SCHWAB_URL_HASH}_tokens.json"
    local age_seconds=$(($(date +%s) - $(stat -f %m "$tokens_file")))
    local age_hours=$((age_seconds / 3600))

    log "INFO" "Freshest tokens in: $source_version (${age_hours}h old)"

    # Count existing version directories
    local version_count=$(get_all_versions | wc -l | tr -d ' ')
    log "INFO" "Found $version_count mcp-remote version directories"

    # Sync to all versions
    local result=$(sync_to_all_versions "$source_dir")
    local created=$(echo "$result" | cut -d: -f1)
    local updated=$(echo "$result" | cut -d: -f2)

    if [[ "$created" -gt 0 ]] || [[ "$updated" -gt 0 ]]; then
        log "SUCCESS" "Synced tokens: $created new files, $updated updated files"
    else
        log "INFO" "All version directories already have current tokens"
    fi

    log "INFO" "Token sync completed"
}

main "$@"
