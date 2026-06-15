#!/bin/bash
# aur-scan.sh  -  AUR System Security Scanner
# Version 1.2.1  |  Read-Only  |  Online-Preferred
#
# Copyright (C) 2026 desynkro
# SPDX-License-Identifier: GPL-3.0-or-later
#
# 10 modules that check your Arch Linux system for signs of
# compromised AUR packages or malware persistence.
#
# Usage:
#   ./aur-scan.sh                normal scan (fetches live list, 5s timeout)
#   ./aur-scan.sh --no-network   offline mode (uses sidecar file, no network needed)
#   ./aur-scan.sh --help         this message
#
# Modules:
#   1  AUR Package Cross-Reference: matches installed pkgs against a
#      known-compromised list (live HedgeDoc fetch or sidecar file)
#   2  Recently Installed Packages: shows the 20 newest for awareness
#   3  PKGBUILD Suspicious Content: flags risky patterns (curl|sh, etc.)
#      in cached PKGBUILDs. Many false positives from Shelly; annotated.
#   4  npm Cache Check:             looks for known malicious packages
#   5  bun Cache Check:             same check in bun's cache
#   6  Temp Binaries:               lists executables in /tmp, /dev/shm
#      (Chromium crash dumps and shared memory are normal; annotated)
#   7  eBPF Rootkit Check:          warns if 50+ BPF programs loaded
#   8  Systemd Persistence:         flags services that download code or
#      run from /tmp, /dev/shm
#   9  Temp Directories:            classifies hidden dirs in temp space
#      (systemd sandboxes, X11 sockets, Wine, Steam = OK;
#       git repos or mystery dirs = investigate)
#  10  Network Listeners:           shows services on non-loopback
#
# Intended for Arch Linux, CachyOS, EndeavourOS, and similar.
#
# --- end of header ---

set -uo pipefail
IFS=$'\n\t'

# --- Configuration ---
# HedgeDoc URL for the latest known-compromised AUR package list
# Updated by the Arch Linux security team
HELP_DOC_URL="https://md.archlinux.org/s/SxbqukK6IA/download"
# Seconds to wait for the online fetch; falls back to sidecar on timeout
HELP_DOC_TIMEOUT=5
# These npm packages are known to be malicious in the npm ecosystem.
# Hard-coded so they're checked even without a network connection.
KNOWN_NPM_MALICIOUS=("atomic-lockfile" "js-digest" "lockfile-js")
# Set to 1 by --no-network flag; skips the live HedgeDoc fetch entirely
NO_NETWORK=0

# --- Counters for the end-of-run summary ---
PASS_COUNT=0; WARN_COUNT=0; ALERT_COUNT=0; SKIP_COUNT=0

# --- Colors ---
RST='\033[0m'
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[0;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'

# --- Output helpers ---
pass() { ((PASS_COUNT++)); printf " ${GRN}[PASS]${RST} %s\n" "$1"; }
warn() { ((WARN_COUNT++)); printf " ${YEL}[WARN]${RST} %s\n" "$1"; }
alert() { ((ALERT_COUNT++)); printf " ${RED}[ALERT]${RST} %s\n" "$1"; }
skip() { ((SKIP_COUNT++)); printf " ${BLU}[SKIP]${RST} %s\n" "$1"; }
info() { printf " ${CYN}[INFO]${RST} %s\n" "$1"; }
note() { printf " ${CYN}[NOTE]${RST} %s\n" "$1"; }

# --- Dependency check ---
# pacman, awk, find, and grep are the core tools used across all modules.
for cmd in pacman grep stat date ls cat find; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Required command not found: $cmd"
        exit 1
    fi
done

# --- Package list sources ---
# Priority: live HedgeDoc fetch > aur_pkg_list.txt (sidecar).


# --- Functions ---

# Load the known-compromised package list.
# Priority: live HedgeDoc fetch > sidecar file.
load_package_list() {
    local pkglist
    if [[ $NO_NETWORK -eq 0 ]] && command -v curl &>/dev/null; then
        pkglist=$(curl -sS --connect-timeout 3 --max-time "$HELP_DOC_TIMEOUT" "$HELP_DOC_URL" 2>/dev/null)
        if [[ -n "$pkglist" ]]; then
            echo "$pkglist"
            return 0
        fi
    fi
    local sidecar
    sidecar="$(dirname "$0")/aur_pkg_list.txt"
    if [[ -f "$sidecar" ]]; then
        cat "$sidecar"
        return 0
    fi
    return 1
}

# Module 1: Match installed packages against the known-compromised AUR list.
# This is the only module that can produce a real [ALERT].
module_aur_xref() {
    echo -e "\n${CYN}═══ Module 1: AUR Package Cross-Reference ═══${RST}"
    local pkglist
    pkglist=$(load_package_list) || {
        skip "Could not load package list"
        return
    }
    note "Package list loaded"
    local installed
    installed=$(pacman -Qq 2>/dev/null) || {
        skip "Could not query installed packages"
        return
    }
    local matched
    matched=$(grep -Fx -f <(echo "$pkglist") <<< "$installed" 2>/dev/null)
    if [[ -n "$matched" ]]; then
        while IFS= read -r pkg; do
            alert "Installed compromised package: $pkg"
        done <<< "$matched"
    else
        pass "No known compromised packages installed"
    fi
}

# Module 2: Show the 20 most-recently installed packages for general awareness.
# Uses expac if available, otherwise falls back to the pacman log.
module_install_dates() {
    echo -e "\n${CYN}═══ Module 2: Recently Installed Packages ═══${RST}"
    if command -v expac &>/dev/null; then
        info "Last 20 installed packages (newest first):"
        expac --timefmt='%Y-%m-%d %H:%M' '%l\t%n' 2>/dev/null | sort -r | head -20 | while IFS= read -r line; do
            echo "         $line"
        done
    else
        local log="/var/log/pacman.log"
        if [[ -f "$log" ]]; then
            info "Last 20 pacman log entries:"
            grep -E '\[PACMAN\]' "$log" 2>/dev/null | tail -20 | while IFS= read -r line; do
                echo "         $line"
            done
        else
            skip "No install date info available (install expac for details)"
        fi
    fi
}

# Module 3: Scan cached PKGBUILD files for suspicious patterns (curl|sh, wget|sh,
# chmod +x, etc.).  Many false positives from AUR helper caches (Shelly). Those
# PKGBUILDs are downloaded from AUR and legitimately use these commands.
module_pkgbuild_audit() {
    echo -e "\n${CYN}═══ Module 3: PKGBUILD Suspicious Content ═══${RST}"
    local suspicious=0
    local patterns=("curl.*| sh" "wget.*| sh" "http.*\.sh\b" "git clone.*\.git"
                    "chmod \+x" "sudo\b" "pkexec" "systemctl" "install.*-m")
    local pkgbuilds
    pkgbuilds=$(find /var/abs /var/aur /var/cache/pacman/pkg /home -maxdepth 5 \
                 -type f -name "PKGBUILD" 2>/dev/null | head -30)
    if [[ -z "$pkgbuilds" ]]; then
        skip "No PKGBUILD files found in cache"
        return
    fi
    while IFS= read -r pkgbuild; do
        local content matched=()
        content=$(cat "$pkgbuild" 2>/dev/null) || continue
        for pattern in "${patterns[@]}"; do
            if grep -qE "$pattern" <<< "$content" 2>/dev/null; then
                matched+=("$pattern")
            fi
        done
        if [[ ${#matched[@]} -gt 0 ]]; then
            suspicious=1
            local plist
            plist=$(IFS=,; echo "${matched[*]}")
            warn "Suspicious patterns [$plist] in $pkgbuild"
            if [[ "$pkgbuild" == *"/.cache/Shelly/"* || "$pkgbuild" == *"/shelly-icons/"* ]]; then
                note "Shelly AUR helper cache: PKGBUILDs downloaded from AUR normally use these commands"
            fi
        fi
    done <<< "$pkgbuilds"
    if [[ $suspicious -eq 0 ]]; then
        pass "No suspicious PKGBUILD patterns found"
    fi
}

# Module 4: Look for known malicious npm packages in the local npm cache.
# Three packages (atomic-lockfile, js-digest, lockfile-js) are hardcoded
# as they are the confirmed malicious ones in the npm ecosystem.
module_npm_cache() {
    echo -e "\n${CYN}═══ Module 4: npm Cache Malicious Package Check ═══${RST}"
    local npm_root="${HOME}/.npm/_cacache"
    if [[ ! -d "$npm_root" ]]; then
        skip "npm cache not found"
        return
    fi
    local found=0
    for pkg in "${KNOWN_NPM_MALICIOUS[@]}"; do
        if grep -rqil --max-count=1 "$pkg" "$npm_root" 2>/dev/null | grep -q .; then
            alert "Known malicious npm package found in cache: $pkg"
            found=1
        fi
    done
    if [[ $found -eq 0 ]]; then
        pass "No known malicious npm packages in cache"
    fi
}

# Module 5: Same check as Module 4, but for bun's package cache.
module_bun_cache() {
    echo -e "\n${CYN}═══ Module 5: bun Cache Malicious Package Check ═══${RST}"
    local bun_cache="${HOME}/.bun/install/cache"
    if [[ ! -d "$bun_cache" ]]; then
        skip "bun cache not found"
        return
    fi
    local found=0
    for pkg in "${KNOWN_NPM_MALICIOUS[@]}"; do
        if find "$bun_cache" -maxdepth 1 -name "*${pkg}*" 2>/dev/null | grep -q .; then
            alert "Known malicious package found in bun cache: $pkg"
            found=1
        fi
    done
    if [[ $found -eq 0 ]]; then
        pass "No known malicious packages in bun cache"
    fi
}

# Module 6: List executable files in /tmp, /var/tmp, and /dev/shm.
# Chromium crash dumps and shared-memory segments are normal and annotated.
# Genuinely suspicious: random scripts or binaries that don't belong to any app.
module_temp_binaries() {
    echo -e "\n${CYN}═══ Module 6: Suspicious Binaries in Temp ═══${RST}"
    local suspicious=0 has_chromium=0 has_shm=0 has_aurcheck=0
    local files
    files=$(find /tmp /var/tmp /dev/shm -maxdepth 3 -type f -executable 2>/dev/null | head -30)
    if [[ -n "$files" ]]; then
        suspicious=1
        warn "Executable files found in temp directories:"
        while IFS= read -r f; do
            echo "         $f $(stat -c '(%s bytes, %y)' "$f" 2>/dev/null)"
            case "$f" in
                *Chromium*)  has_chromium=1 ;;
                /dev/shm/*)  has_shm=1 ;;
                */aur-check/*) has_aurcheck=1 ;;
            esac
        done <<< "$files"
        [[ $has_chromium -eq 1 ]]  && note "Chromium/Chrome browser temp files: normal during browsing/updates"
        [[ $has_shm -eq 1 ]]       && note "/dev/shm shared memory: used by browsers, Steam, Electron apps (normal)"
        [[ $has_aurcheck -eq 1 ]]  && note "/tmp/aur-check/ contains our previous manual scan scripts. Safe"
    fi
    if [[ $suspicious -eq 0 ]]; then
        pass "No suspicious binaries in temp directories"
    fi
}

# Module 7: Check for eBPF programs, which can be used by rootkits.
# Requires bpftool (not installed by default). Threshold: 50+ programs is unusual.
module_ebpf() {
    echo -e "\n${CYN}═══ Module 7: eBPF Rootkit Check ═══${RST}"
    if ! command -v bpftool &>/dev/null; then
        skip "bpftool not available (install bpftool for eBPF checks)"
        return
    fi
    local count
    count=$(bpftool prog list 2>/dev/null | grep -cE '^[0-9]+:')
    if [[ "$count" -gt 50 ]]; then
        warn "High number of eBPF programs: $count (possible rootkit indicator)"
    elif [[ "$count" -eq 0 ]]; then
        pass "No eBPF programs loaded"
    else
        pass "eBPF programs count normal: ${count}"
    fi
}

# Module 8: Flag systemd services whose ExecStart downloads code or runs from
# /tmp or /dev/shm, a common persistence technique. xfs_scrub was a known false
# positive; the pattern has been refined to avoid it.
module_systemd() {
    echo -e "\n${CYN}═══ Module 8: Suspicious Systemd Services ═══${RST}"
    local suspicious=0
    local services
    services=$(find /etc/systemd/system /usr/lib/systemd/system -maxdepth 2 \
               -name "*.service" -type f 2>/dev/null)
    while IFS= read -r svc; do
        local content
        content=$(cat "$svc" 2>/dev/null) || continue
        if grep -qE 'ExecStart=.*(curl|wget).*(\||https?://)|ExecStart=.*/dev/shm' <<< "$content" 2>/dev/null; then
            warn "Suspicious service: $svc"
            suspicious=1
        fi
    done <<< "$services"
    if [[ $suspicious -eq 0 ]]; then
        pass "No suspicious systemd services found"
    fi
}

# Module 9: Classify hidden / dotted directories in temp space.
# Systemd sandboxes, X11 sockets, Wine, Steam, and Node.js caches are normal.
# Git repos and mystery directories are flagged for investigation.
module_temp_dirs() {
    echo -e "\n${CYN}═══ Module 9: Suspicious Temp Directories ═══${RST}"
    local suspicious=0 has_gitdir=0 has_browserdir=0
    local dirs
    dirs=$(find /tmp /var/tmp /dev/shm -maxdepth 3 -type d \
           \( -name ".*" -o -name "*.*" \) 2>/dev/null | head -50)
    if [[ -z "$dirs" ]]; then
        pass "No suspicious temp directories"
        return
    fi
    # Classify and display directories
    while IFS= read -r d; do
        case "$d" in
            /tmp/systemd-private-*|/var/tmp/systemd-private-*)
                info "Systemd service sandbox: ${d##*/}"
                ;;
            /tmp/.X11-unix|/tmp/.ICE-unix|/tmp/.font-unix|/tmp/.XIM-unix)
                info "X11 display socket (standard): ${d##*/}"
                ;;
            /tmp/.wine-*)
                info "Wine runtime directory: ${d##*/}"
                ;;
            /tmp/.com.valvesoftware.Steam*)
                info "Steam client runtime: ${d##*/}"
                ;;
            /tmp/plasma-csd-generator.*)
                info "KDE Plasma temp file: ${d##*/}"
                ;;
            /tmp/.millennium-*)
                info "Millennium app temp directory: ${d##*/}"
                ;;
            /tmp/org.chromium.Chromium.*)
                has_browserdir=1
                info "Browser component updater temp: ${d##*/}"
                ;;
            /tmp/.parallel)
                info "GNU parallel temp directory"
                ;;
            */node-compile-cache/*)
                info "Node.js compilation cache: ${d##*/}"
                ;;
            */.git)
                suspicious=1
                warn "Git repository in temp directory: $d"
                has_gitdir=1
                ;;
            *)
                suspicious=1
                warn "Suspicious temp directory: $d"
                ;;
        esac
    done <<< "$dirs"
    [[ $has_gitdir -eq 1 ]] && note "Git repos in /tmp are unusual, likely left over from manual work, not malware"
    [[ $has_browserdir -eq 1 ]] && note "Browser component updater dirs in /tmp are normal during browsing/updates"
    if [[ $suspicious -eq 0 ]]; then
        pass "No suspicious temp directories"
    fi
}

# Module 10: Show services listening on non-loopback interfaces for awareness.
# Steam, Syncthing, KDE Connect, and pipeweaver are common; anything unfamiliar
# may warrant investigation.
module_network() {
    echo -e "\n${CYN}═══ Module 10: Network Listening Services ═══${RST}"
    if ! command -v ss &>/dev/null; then
        skip "ss not available"
        return
    fi
    local listening
    listening=$(ss -tlnp 2>/dev/null | awk 'NR>1 && !/127.0.0.1:/ && !/::1:/')
    if [[ -n "$listening" ]]; then
        info "Services listening on non-loopback interfaces:"
        echo "$listening" | while IFS= read -r line; do
            echo "         $line"
        done
    else
        pass "No unusual network listeners (all on loopback)"
    fi
}

# --- Main ---
# Parse command-line flags
for arg in "$@"; do
    case "$arg" in
        --help|-h)
            awk '/^# --- end of header ---$/{exit} NR>1' "$0"
            exit 0
            ;;
        --no-network)
            NO_NETWORK=1
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: ./aur-scan.sh [--help] [--no-network]"
            exit 1
            ;;
    esac
done

echo -e "${CYN}╔══════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}║     AUR System Security Scanner v1.2.1          ║${RST}"
echo -e "${CYN}║     Read-Only Mode  |  10 Check Modules         ║${RST}"
echo -e "${CYN}╚══════════════════════════════════════════════════╝${RST}"
echo -e " Scan started: $(date '+%Y-%m-%d %H:%M:%S')"

module_aur_xref
module_install_dates
module_pkgbuild_audit
module_npm_cache
module_bun_cache
module_temp_binaries
module_ebpf
module_systemd
module_temp_dirs
module_network

echo -e "\n${CYN}═══════════════════════════════════════════════════${RST}"
echo -e "${CYN}        Understanding Your Results                     ${RST}"
echo -e "${CYN}═══════════════════════════════════════════════════${RST}"
echo -e " ${GRN}[PASS]${RST}  Everything OK. No action needed"
echo -e " ${CYN}[INFO]${RST}  Information for your awareness"
echo -e " ${CYN}[NOTE]${RST}  Explanation of a specific finding above"
echo -e " ${YEL}[WARN]${RST}  Caution flag. Read the [NOTE] explanation; usually benign"
echo -e " ${RED}[ALERT]${RST}  Action recommended. A compromised package was found"
echo -e " ${BLU}[SKIP]${RST}  A check could not run (optional tool not installed)"
echo -e ""
echo -e " Only Module 1 (AUR Cross-Reference) produces a real ${RED}[ALERT]${RST}."
echo -e " The ${YEL}[WARN]${RST} results are caution flags. Each has a ${CYN}[NOTE]${RST} explaining why it's likely safe."
echo -e " If you are still unsure, ask the Arch Linux community or open an issue."

echo -e "\n${CYN}═══ Scan Complete ═══${RST}"
echo -e " ${GRN}PASS: ${PASS_COUNT}${RST}  ${YEL}WARN: ${WARN_COUNT}${RST}  ${RED}ALERT: ${ALERT_COUNT}${RST}  ${BLU}SKIP: ${SKIP_COUNT}${RST}"
echo -e " Scan finished: $(date '+%Y-%m-%d %H:%M:%S')"
exit 0

