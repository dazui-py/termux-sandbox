#!/usr/bin/env bash

# Path helper functions for termux-sandbox

# Base directory for all sandboxes
TERMUX_SANDBOX_DIR="${HOME}/.termux-sandbox"

# Subdirectories
TERMUX_SANDBOX_BOXES_DIR="${TERMUX_SANDBOX_DIR}/boxes"
TERMUX_SANDBOX_CACHE_DIR="${TERMUX_SANDBOX_DIR}/cache"
TERMUX_SANDBOX_ROOTFS_CACHE_DIR="${TERMUX_SANDBOX_CACHE_DIR}/rootfs"
TERMUX_SANDBOX_CONFIG_DIR="${TERMUX_SANDBOX_DIR}/config"

# Ensure base directories exist
ensure_dirs() {
    mkdir -p "$TERMUX_SANDBOX_BOXES_DIR"
    mkdir -p "$TERMUX_SANDBOX_ROOTFS_CACHE_DIR"
    mkdir -p "$TERMUX_SANDBOX_CONFIG_DIR"
}

# Get the path to a specific sandbox
get_sandbox_path() {
    local name="$1"
    echo "${TERMUX_SANDBOX_BOXES_DIR}/${name}"
}

# Get the rootfs path for a sandbox
get_sandbox_rootfs_path() {
    local name="$1"
    echo "$(get_sandbox_path "$name")/rootfs"
}

# Get metadata file path
get_metadata_path() {
    local name="$1"
    echo "$(get_sandbox_path "$name")/metadata.conf"
}

# Get policy file path
get_policy_path() {
    local name="$1"
    echo "$(get_sandbox_path "$name")/policy.conf"
}

# Get grants file path
get_grants_path() {
    local name="$1"
    echo "$(get_sandbox_path "$name")/grants.conf"
}

# Get logs directory path
get_logs_path() {
    local name="$1"
    echo "$(get_sandbox_path "$name")/logs"
}

# Check if sandbox exists
sandbox_exists() {
    local name="$1"
    [[ -d "$(get_sandbox_path "$name")" ]]
}
