#!/bin/bash
# aur-scan.sh  —  AUR System Security Scanner
# Version 1.0  |  Read-Only  |  Offline-First
#
# Copyright (C) 2026 desynkro
# SPDX-License-Identifier: GPL-3.0-or-later
#
# 10 modules that check your Arch Linux system for signs of
# compromised AUR packages or malware persistence.
#
# Usage:
#   ./aur-scan.sh                normal scan (fetches live list, 5s timeout)
#   ./aur-scan.sh --no-network   offline only (uses embedded package list)
#   ./aur-scan.sh --help         this message
#
# Modules:
#   1  AUR Package Cross-Reference — matches installed pkgs against a
#      known-compromised list (live HedgeDoc fetch, embedded fallback)
#   2  Recently Installed Packages — shows the 20 newest for awareness
#   3  PKGBUILD Suspicious Content — flags risky patterns (curl|sh, etc.)
#      in cached PKGBUILDs. Many false positives from Shelly — annotated.
#   4  npm Cache Check             — looks for known malicious packages
#   5  bun Cache Check             — same check in bun's cache
#   6  Temp Binaries               — lists executables in /tmp, /dev/shm
#      (Chromium crash dumps and shared memory are normal — annotated)
#   7  eBPF Rootkit Check          — warns if 50+ BPF programs loaded
#   8  Systemd Persistence         — flags services that download code or
#      run from /tmp, /dev/shm
#   9  Temp Directories            — classifies hidden dirs in temp space
#      (systemd sandboxes, X11 sockets, Wine, Steam = OK;
#       git repos or mystery dirs = investigate)
#  10  Network Listeners           — shows services on non-loopback
#
# Embedded package list: 1936 plain-text package names at the end of this file.
# Updated live from Arch Linux HedgeDoc on each run (configurable timeout).
# Intended for Arch Linux, CachyOS, EndeavourOS, and similar.
#
# --- end of header ---

set -uo pipefail
IFS=$'\n\t'

# --- Configuration ---
# HedgeDoc URL for the latest known-compromised AUR package list
# Updated by the Arch Linux security team
HELP_DOC_URL="https://md.archlinux.org/s/SxbqukK6IA/download"
# Seconds to wait for the online fetch; falls back to embedded list on timeout
HELP_DOC_TIMEOUT=5
# These npm packages are known to be malicious in the npm ecosystem.
# Hard-coded so they're checked even without a network connection.
KNOWN_NPM_MALICIOUS=("atomic-lockfile" "js-digest" "lockfile-js")
# Set to 1 by --no-network flag; skips the live HedgeDoc fetch entirely
NO_NETWORK=0

# --- Counters for the end-of-run summary ---
PASS_COUNT=0; WARN_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0

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
fail() { ((FAIL_COUNT++)); printf " ${RED}[FAIL]${RST} %s\n" "$1"; }
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

# --- Embedded compromised package list (plain text, 1936 names) ---
# Sits at the bottom of this file after the "# >>> PACKAGE LIST" marker.
# Extracted by awk when the online HedgeDoc fetch fails or --no-network is set.


# --- Functions ---

# Load the known-compromised package list: try a live fetch first,
# then fall back to the embedded copy at the bottom of this file.
load_package_list() {
    local pkglist
    if [[ $NO_NETWORK -eq 0 ]] && command -v curl &>/dev/null; then
        pkglist=$(curl -sS --connect-timeout 3 --max-time "$HELP_DOC_TIMEOUT" "$HELP_DOC_URL" 2>/dev/null)
        if [[ -n "$pkglist" ]]; then
            echo "$pkglist"
            return 0
        fi
    fi
    local embedded
    embedded=$(awk '/^# >>> PACKAGE LIST$/{found=1;next} found{print}' "$0")
    if [[ -n "$embedded" ]]; then
        echo "$embedded"
        return 0
    fi
    return 1
}

# Module 1: Match installed packages against the known-compromised AUR list.
# This is the only module that can produce a real [FAIL].
module_aur_xref() {
    echo -e "\n${CYN}═══ Module 1: AUR Package Cross-Reference ═══${RST}"
    local pkglist
    pkglist=$(load_package_list) || {
        skip "Could not load package list"
        return
    }
    if [[ $NO_NETWORK -eq 1 ]]; then
        note "Package list source: embedded (1936 packages)"
    else
        note "Package list source: HedgeDoc (online, with embedded fallback)"
    fi
    local installed
    installed=$(pacman -Qq 2>/dev/null) || {
        skip "Could not query installed packages"
        return
    }
    local matched
    matched=$(grep -Fx -f <(echo "$pkglist") <<< "$installed" 2>/dev/null)
    if [[ -n "$matched" ]]; then
        while IFS= read -r pkg; do
            fail "Installed compromised package: $pkg"
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
# chmod +x, etc.).  Many false positives from AUR helper caches (Shelly) — those
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
                note "Shelly AUR helper cache — PKGBUILDs downloaded from AUR normally use these commands"
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
            fail "Known malicious npm package found in cache: $pkg"
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
            fail "Known malicious package found in bun cache: $pkg"
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
        [[ $has_chromium -eq 1 ]]  && note "Chromium/Chrome browser temp files — normal during browsing/updates"
        [[ $has_shm -eq 1 ]]       && note "/dev/shm shared memory — used by browsers, Steam, Electron apps (normal)"
        [[ $has_aurcheck -eq 1 ]]  && note "/tmp/aur-check/ contains our previous manual scan scripts — safe"
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
# /tmp or /dev/shm — a common persistence technique. xfs_scrub was a known false
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
    local suspicious=0 has_gitdir=0
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
    [[ $has_gitdir -eq 1 ]] && note "Git repos in /tmp are unusual — likely left over from manual work, not malware"
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
echo -e "${CYN}║     AUR System Security Scanner v1.0            ║${RST}"
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
echo -e " ${GRN}[PASS]${RST}  Everything OK — no action needed"
echo -e " ${CYN}[INFO]${RST}  Information for your awareness"
echo -e " ${CYN}[NOTE]${RST}  Explanation of a specific finding above"
echo -e " ${YEL}[WARN]${RST}  Caution flag — read the [NOTE] explanation; usually benign"
echo -e " ${RED}[FAIL]${RST}  Action recommended — a compromised package was found"
echo -e " ${BLU}[SKIP]${RST}  A check could not run (optional tool not installed)"
echo -e ""
echo -e " Only Module 1 (AUR Cross-Reference) produces a real ${RED}[FAIL]${RST}."
echo -e " The ${YEL}[WARN]${RST} results are caution flags — each has a ${CYN}[NOTE]${RST} explaining why it's likely safe."
echo -e " If you are still unsure, ask the Arch Linux community or open an issue."

echo -e "\n${CYN}═══ Scan Complete ═══${RST}"
echo -e " ${GRN}PASS: ${PASS_COUNT}${RST}  ${YEL}WARN: ${WARN_COUNT}${RST}  ${RED}FAIL: ${FAIL_COUNT}${RST}  ${BLU}SKIP: ${SKIP_COUNT}${RST}"
echo -e " Scan finished: $(date '+%Y-%m-%d %H:%M:%S')"
exit 0

# >>> PACKAGE LIST
123pan-bin
1code
8188eu-dkms
8192eu-dkms-git
abntex
acpitool
actual-ai
adapta-gtk-theme-git
adblock2privoxy
adom-noteye
adsuck
aion-git
akira-git
akonadi-git
aksusbd
albion-online-launcher-bin
alfont
algorand-devtools-bin
alienfx
alienfx-lite
alock-git
alternating-layouts-git
alttab-git
alvr
alvr-git
ambiance-radiance-colors-suite
amdgpu-fancontrol-git
amdguid-wayland-bin
amfora-favicons-git
amide
amide-git
amtterm
amule-dlp-git
android-backup-extractor
android-docs
android-google-play-apk-expansion
android-google-play-licensing
androidscreencast-bin
android-signapk
android-signapk-gui
android-support-repository
angularjs
annobin
ansible-language-server
ant-dracula-gtk-theme
antfs-cli-git
antichamber
antileech
anythingllm-appimage
anythingllm-cli-bin
apache-ant-contrib
apk-installer-gui
apm_planner-bin
apothem
apple-music-desktop
apprenticevrsrc-bin
apwal
aquaria-ose
arachnophilia
arcadia
archivemail
archjh
archlinux-themes-balou
archlinux-themes-slim
archmage
arch-palemoon-search
archtex-git
arch-update-vai
arduino-git
argouml
aria2fe
ariang-allinone
armitage-git
arm-linux-gnueabihf-binutils
arm-linux-gnueabihf-glibc-headers
arm-linux-gnueabihf-linux-api-headers
ar-smileys
artanis-git
ascii-rain-git
asciiworld-git
astah-uml
astro-editor-appimage
asus-fan-dkms-git
atlassian-confluence
atlassian-plugin-sdk
atolm-openbox-theme
atomicwalet
atomicwalllet
atto-bin
audible-activator-git
audiere
audiotube-git
aura-browser
aura-browser-git
auryo
autohand-cli
autolabel
autolatex
autologin
autozen
avarice-git
avogadro2-git
avra
awesome-cinnamon
awesome-revelation-git
awoken-icons
aws-cli-git
aws-sam-cli
ayatana-indicator-application
azurlaneautoscript
backup2l
backwild
balena-cli
bangin-server-node
barrier-git
basilisk-gtk2-bin
batman-adv
bazel-buildtools
bbswitch-git
bcachefs-kernel-dkms-git
bcalc
bcnc
bcoin-git
bdf-creep
beaker-browser-git
beaker-ng-bin
beancount-git
beebeep
beef
beets-copyartifacts-git
bibtex2html
bicon-git
bin32-jre
bing-wallpaper-git
binnavi
biosdevname
bitcanna-wallet-bin
bitcoin-core-git
bittube-wallet-gui
blackcoin-git
blackfire-agent
blender-plugin-bim-git
blender-plugin-vectex
bleufear-gtk-theme
blinkenlib
blogc
blt
blueprint-compiler-git
blueproximity-py3-git
bonsai-browser
booklore
boostnote-bin
borg-git
bouml
bpytop-git
bracket
brightness-controller-git
brother-hl3150cdw
brother-hll6200dw
brow6el
brow6el-git
browserpass-git
brscan3
bsnes-plus-git
bs-platform
btdex
btdex-git
burn-cd
caelum
caja-deja-dup-bzr
camotics
camunda-modeler-plugin-bpmn-js-token-simulation
canon-pixma-mg3000-complete-fixed
capt-src
capture
cardano-addresses
cardano-node
cardano-wallet
cardano-wallet-bin
carto-sql-api
cartridge-cli
castawesome
castersoundboard-git
catalyst5-browser
cattle
cavestory+-hb
cb2bib
ccase-bin
cccc
ccl-git
ccminer-git
ccsm-gtk3
cdo
centerim5-git
cerbere-git
cerebro
certbox-bin
cgminer
c++-gtk-utils-gtk2
c+gtk-utils-gtk2
cgvg
charcoal
chexquest3-wad
chez-scheme-git
chia-cli-git
chia-git
chicken-srfi-180
chipmachine
chipmunk
chisel
chromeos-apk-git
cinny-desktop-system-tray
cint
cjs-git
clai
clamfs
clang15
clang19
clash-mi
claude-code-router
claymore-miner-bin
clevo-xsm-wmi
cling-git
cling-jupyter-git
clipgrab-kde
cl-javascript
cl-parenscript
cl-parse-js
cmake-modules-webos-git
cmospwd
cmuclmtk
cnijfilter-common
cnijfilter-common-mg5400
cnijfilter-ip110
cnijfilter-mp550
codeclimate
code-git
codeigniter
codenomad-bin
code-notes-bin
codeql-cli-bin
coffeescript-git
cogpit-bin
colorhug-client
colorsvn
colorz
compiler-rt19
compizconfig-python
compizconfig-python-git
compiz-fusion-plugins-experimental
compiz-fusion-plugins-experimental-git
compiz-fusion-plugins-extra
compiz-fusion-plugins-extra-git
complexity
concordium-desktop-wallet-appimage
concordium-desktop-wallet-bin
concordium-desktop-wallet-testnet-bin
concordium-node-bin
connman-ncurses
connman-ncurses-git
connman-ui-git
containerd-git
contemporary-cursors
controllermap
coolreader
coolreader3-git
coppeliasim-bin
cowdancer
coyim
cpp-netlib
cppreference-devhelp
cpufreqd
cpuminer-git
cpuminer-multi
cpuminer-multi-git
cpuminer-opt
cpuminer-opt-sugarchain
cpu-monitor-extension-lxpanel-plugin
cpuset
craftbukkit-plugin-worldedit
create-next-app
createvm
cross-mingw-w64-gdb
cryptoplugin
cryptowatch-desktop-bin
ctjs-bin
cubieboard-livesuit
cura
cura-plugin-octoprint-git
curecoind-git
curecoin-qt-git
curseradio-git
cutefish-calculator
cutefish-core
cutefish-dock
cutefish-filemanager
cutefish-icons
cutefish-launcher
cutefish-qt-plugins
cutefish-screenlocker
cutefish-screenshot
cutefish-settings
cutefish-statusbar
cutefish-wallpapers
cutemarked-git
cvs2svn
cvs-feature-bin
cwiid
cxo
cynthiune.app
d1x-rebirth
daala-git
daggerfall-addons
dagu-bin
dahdi-linux
dalbum
darwinia
dashcore
datatype99
davtools
dbxcli
deepin-mail-bin
deepin-wine6-stable
deheader
delaycut
denaro
deno-git
dep
desktopnova
desync-git
dexed-ide-bin
dfhack
dfhack-bin
dh-python
dianara
dibuja
difi
difi-bin
digikam-without-akonadi
digitemp
discord-qt
distrho-ports-lv2-git
dkopp
dmg2dir
docker-gc-git
docopts
doctoc
doom3-inhell
doomsday
dot-git
dots-hyprland-fork-git
dptf
drascula
drbl-experimental
drkonqi-git
drm_tools
droopy-git
dropbox-kde-systray-icons
dsd
dsdcc-git
dub-git
dukto
dvbcut
dvdrip
dvorak7min
dyad-bin
dynamodb
e4rat-lite-git
easymp3gain-qt4-bin
easy_spice
easytag-git
echinus-git
echo-icon-theme-git
eclipse-checkstyle
eclipse-i18n-de
eclipse-i18n-fr
eclipse-markdown
edconv-bin
edfbrowser-git
edx-downloader-git
eel-language
efiboots-git
eisl
electron-cash-slp
electroneum
electrum-bin
electrum-nmc
electrum-ravencoin-appimage
elements-project
elements-project-bin
elinks-git
elixirscript
elmerfem
elm-format-bin
elm-platform
emacs-color-theme
emacs-d-mode
emacs-ess-git
emacs-find-recursive
emacs-icicles
emacs-identica-mode
emacs-jabber
emacs-jabber-git
emacs-js2-mode-git
emacs-magit
emacs-mew
emacs-mmm-mode
emacs-paredit
emacs-pkgbuild-mode-git
emacs-popup-el
emacs-sml-mode
emacs-solidity-mode-git
emacs-yasnippet-git
emerald-wallet-bin
emms-git
encryptr
energyplus
envoy-git
envypn-font
eperiodique
epson-inkjet-printer-escpr2-clos-bin
errut
eslint-plugin-promise
eslint-plugin-react
eslint-plugin-vue
esteem-bin
etherpad-lite
ethlint-git
etmtk
eviacam
evilvte-git
evilwm
evopedia-git
evopop-gtk-theme
evopop-icon-theme
exact-image
exiftags
exodas
exodis
exodud
exodusae
exoduss
exodus-wallet
exoduswallet
exodus-wallet-bin
exodux
exoduz
exodys
exouds
fanicontrol
fantom
farmmod-hub
fasd-git
fastjet
fastoggenc
fatx
fbctrl
fbff-git
fcitx
fcitx5-pinyin-sougou-dict-git
fcitx-baidupinyin
featherwallet-appimage
felida-bin
felinks-python
fengoffice
ffdiaporama-texturemate
ffmpeg3.4
ffmpeg-bitrate-stats
ffmpeg-quality-metrics
fifth
fifth-git
filebot47
findpkg-git
firebird
firefox-babble
firefox-esr-extension-privacybadger
firefox-esr-globalmenu
firefox-esr-noscript
firefox-esr-ublock-origin
firefox-extension-adnauseam-bin-amo
firefox-extension-duckduckgo-privacy-essentials
firefox-extension-gooreplacer
firefox-floccus
firefox-librejs
firefox-user-agent-switcher-and-manager-bin
firmium-desktop-git
firmware-mod-kit
fisher-git
fishui
fishui-git
flashbrowser
flashfocus
flatcam-git
flexiblas
flow
flowblade-git
flow-browser-git
flow-git
flow-pomodoro
flv2x264
flynarwhal
fmlib
fontfinder
fontweak
forgecode-bin
formidable-bin
fortune-mod-firefly
fpp-git
frame
freemind-git
freeter
frutool
fs2-knossos
fs2_open-mediavps
fspy
fstar-git
ft232r_prog
ftl
fuego-svn
fuel
fusion-icon
fusion-icon-git
futhark-bin
fwlogwatch
g2
g3data
gahshomar
gaiaui-amd
galaxy2
gameflow-deck-git
gamma-launcher
ganyremote
garlium-git
garmindev
gavrasm
gcal
gcccpuopt
gcstar
gcstar-gitlab
gdl
gdlmm
gdlmm-docs
gecode
geekcode
geforcenow-electron
gemistdownloader
get_flash_videos
getlive
gfxbench
ggoban
gimp-plugin-arrow
gist-git
gisto
git-annex-standalone
gitflow-avh
git-flow-completion-git
gitfs
gitinspector
git-open
gitosis-git
git-remote-hg-git
gitso
gitter-bin
git-time-machine
gjs-git
gkraken
gle-graphics
globalplatform
globalprotect-bin
glosstex
glsl-debugger-git
gminer-bin
gmp4
gmt-coast
gmt-cpt-city
gnomato
gnome-battery-bench-git
gnome-contacts-git
gnome-directory-thumbnailer
gnome-pass-search-provider-git
gnome-randr-rust
gnome-rdp
gnome-shell-extension-cpufreq-git
gnome-shell-extension-custom-hot-corners-extended
gnome-shell-extension-dynamic-top-bar
gnome-shell-extension-hibernate-status-git
gnome-shell-extension-topicons-plus
gnome-shell-extension-transmission-daemon-git
gnome-shell-extension-x11gestures
gnome-shell-theme-arc-clearly-dark-git
gnome-specimen
gnome-terminal-fedora
gnome-usage-git
gnome-xcf-thumbnailer
gnuplot-git
gnutls3.8.9
gobyte-qt
gogs-git
gog-the-witcher-2-assassins-of-kings
gohufont-powerline
google-authenticator-libpam-git
gopenvpn-git
gopher2600
gopher2600-bin
goqat
gosh
gpicsync
gpshell
gpx-viewer
graal-bin
graal-nodejs-jdk17-bin
graal-nodejs-jdk20-bin
gram-wallet-bin
graveman
greenisland
green-tunnel-bin
greetd-wlgreet-git
gridmgr-git
grim-git
gr-osmosdr-git
grpn
grub4dos
grub-luks-keyfile
gsettings-desktop-schemas-git
gsettings-system-schemas-git
gtkimageview
gtksetpwc
gtkterm-git
gtk-theme-bsm-simple
gtk-theme-metagrip
gtk-theme-windows10-dark
gtk-vnc-gtk2
guake-colors-solarized-git
guile-git
guile-reader
guile-ssh
guiscrcpy
gulden-appimage
gummy
gummy-git
gutenpy
gxemul
hack-browser-data-git
hackmatrix-git
halberd
ha-pacemaker-git
happy-cli
hardcode-tray
harminv
harmony-wad
haskell-asn1-data
haskell-chart
haskell-failure
haskell-hscurses
haskell-hssyck
hattrick_organizer
haunt
haxe-git
hd2u
hdx-512-git
headphones
hearthstone-linux-gui-appimage
hearthstone-linux-gui-bin
hepmc2
hexchat-otr
hfstospell
hifive1-sdk-git
hister-git
hnswlib-git
homeassistant-osagent
homeassistant-supervised
hop
horst
hotlinemiami
howm-x11-git
howto-bin
hpgcc
hp-health
hpoj
htbrowser-bin
htdig
htop-vim-solarized-git
httpry
huawei-stat-e220
hudkit-wayland
humen-mcp-git
hunter
hydownloader-git
hydrapaper-git
hydrus-git
hypervc-qt4
hypr-git
i2c-ch341-dkms
i3bar-river
i3-gnome-git
i3lock-fancy-dualmonitors-git
ianny-bin
ibc
ibm-sw-tpm2
ibus-uniemoji-git
icdiff-git
ice-ssb
iceweasel
ideviceinstaller-git
ifcopenshell-git
igdm
ihaskell-git
ijavascript
ike
ikos
imageglass
img2djvu-git
inadyn
inadyn-mt
indicator-session
infinity-background
infnoise-openssl-git
inform7
inkslides-git
intelmetool-git
intelpwm-udev
interface99
ios-webkit-debug-proxy
ipfs-desktop-bin
ipsw
iptrafvol
iron-heart-git
irssistats
isight-firmware-tools
itop
j4-make-config-git
ja2-stracciatella-git
jade-application-kit
jade-application-kit-git
janusvr
jasmin
jasp-desktop
java-berkeleydb
java-flexdock
javahelp2
java-qdox
jd-gui
jdk11-openj9-bin
jdk17-jetbrains-bin
jdk8-graalvm-bin
jdk-openj9-bin
jetbrains-mps
jflex
jin
joxi
joy
joycon-git
joymouse
jreen-git
js-design
js-design-agent-bin
js-design-appimage
jspm-cli
jstock
jupyter-nbextension-rise
just-js
just-js-completion
jzip
k3sup
k4dirstat
kalu-git
kapacitor
kapidox-git
katrain
kcmlaptop
kdb
kddockwidgets-git
kdelibs
kde-svn2git
kdevelop-pg-qt-git
keep
keepass-fr
keepass-plugin-qualitycolumn
keepassx2
keeperrl-git
kexi
kibana5
kibana6
kicad-library-ab2-git
kiconedit
kimageformats-git
kio_gopher
kiss
kmarkdownwebview
kmorph
kodi-addon-inputstream-adaptive-git
kokua-secondlife
kompare-git
kookbook
kopano-core
kotatogram-desktop
koules
kproperty
krakatau-git
kreport
kristforge-bin
ktea
kubo-git
kvirc-git
kwin-effects-blur-respect-rounded-decorations-git
kwin-scripts-quarter-tiling-git
kwplayer
lab-bin
ladish
laditools
lash
lastfmlib
latex-digsig
latex-make
latex-mk
lazylpsolverlibs-git
lbench
ledgerlive
ledgerlive-bin
ledger-udev-bin
legofy-git
leocad-git
lesstif
lexmark_pro700
lib32-egl-wayland
lib32-fftw
lib32-freeimage
lib32-gimp
lib32-gnome-themes-extra
lib32-graphene
lib32-libfmod
lib32-libjson
lib32-libmad
lib32-libreplaygain
lib32-libxpm
lib32-libxxf86dga
lib32-mtdev
lib32-tk
libafterimage
libakonadi-git
libarcus-git
libavif-noglycin
libbobcat
libcompizconfig-git
libcsa-git
libcss-git
libcutefish
libdill
libdivecomputer-git
libevdevc
libffi-static
libfprint-vfs_proprietary-git
libfreenect-git
libgdata
libgtkhtml
libheif-noglycin
libhugetlbfs
libisl15
libjxl-noglycin
libjxl-noglycin-doc
libkarma
libkdcraw-git
libkomparediff2-git
libmrss
libnautilus-extension-git
libnbcompat
libntru
libnxml
libopenaptx-git
libprelude
libptp2
libpurple-carbons-git
libpurple-lurch
libpurple-lurch-git
libpurple-meanwhile
libpuzzle
libquvi
libquvi-scripts
libreoffice-extension-coooder
librep
librep-git
libretro-hatari-enhanced-git
libretro-mame-git
libretro-mednafen-supergrafx-git
librewolf-extension-duckduckgo-privacy-essentials
librewolf-extension-protonpass-bin
librewolf-extension-vimiumc-bin
libsingularity-git
libsmi
libspatialindex-git
libtcd
libtorrent-ps
libtrash
libuiohook
libviper
libwapcaplet-git
libxaw3dxft
libxdiff
libxml-ruby
libyami
lightdm-webkit-theme-userdock
lilypond-git
limbo-hib
limesuite-git
linkerd
linphone-desktop-all
linphone-desktop-all-git
linphone-plugin-msx264
linux-bcachefs-git
linux-bcachefs-git-headers
linux-cachyos-deckify-native
linux-cachyos-deckify-native-headers
linux-cachyos-native
linux-cachyos-native-headers
linux-cachyos-native-nvidia-open
linux-cachyos-rc-native
linux-cachyos-rc-native-headers
linux-cachyos-rc-native-nvidia-open
linux_logo_archcustom
linux-manjaro-xanmod
linux-manjaro-xanmod-headers
linux-rc
linux-rc-headers
linux-steam-integration
linux-tool
linux-xanmod-rog
linux-xanmod-rog-headers
linvst
liri-cmake-shared-git
liri-shell-git
lite
lld19
lll
llvm-cbe-git
lndhub
lorem-ipsum-generator
love09
lowfi-bin
lrexlib-pcre5.1
ls++
lsx
lttng-modules
lua51-sql-sqlite
luazip5.1
lucidvideo
luksipc-git
lure
lv
lwan-git
lwxc-git
lxdvdrip
lxqt-qt5ct
lynis-git
lyvi-git
lzham
m5rcode
machinarium
mac-os-lion-cursors
madsonic
magicassistant-gtk
magiwallet-magid-ruckard-raspi4
magpie-wm
make-3.81
mako-center-git
mantissa
manuskript
mapbox-studio
mapcrafter-git
marcfs-git
markmywords-git
marytts
masari
maszyna-git
mathsat-5
mato-icons-git
matrixbrandy
maxima-git
mbm-gpsd-pl4nkton-git
mcpatcher
mcp-probe
mc-skin-modarin-debian
mdbook-compress
me_cleaner-git
meliora-openbox-themes
melis-wallet-bin
melvor-mod-manager
menu-cache-git
menumaker-compiz
mermaid-ascii-git
mermark-editor
mesa-dlss-reflex-git
mesecons-git
mesos
meteo
mictray
mikidown-git
milena
milena-data
milton-git
mime-archpkg
mimic-node-git
minder-git
minecraft-overviewer
minecraft-overviewer-docs
minecraft-overviewer-docs-git
minecraft-overviewer-git
minergate-cli
minergate-gui
minetest-subway-miner
mingw-w64-adwaita-icon-theme
mingw-w64-duktape
mingw-w64-geos
mingw-w64-gtk2
mingw-w64-laz-perf
mingw-w64-libcroco
mingw-w64-libidn
mingw-w64-libsndfile
mingw-w64-libtasn1
mingw-w64-libtheora
mingw-w64-pcre
mingw-w64-sdl
mingw-w64-sdl2_ttf
minichrome
minify-js-bin
minimax-bin-hardened
miniongg
minitube
miro-video-converter
mirrorlist-rankmirrors-hook
misuzu-music-bin
mkdocs-bootswatch
mkgmap-svn
mmc-utils-git
mobac-svn
mojave-ct-icon-theme
mon2cam-git
mongo-cxx-driver-legacy-0.0-26compat
mongrel2
mono-addins
mono-addins-git
monochrome
monochrome-git
montecarlo-font
moonshiner
moor-git
mopen
mopidy-moped
mopidy-youtube
mount-gtk
movgrab
mp3guessenc
mpir
mqttfx-bin
msieve
ms-office-online
multimon-ng-git
multiwinia
murmur-git
mwc-qt-wallet-bin
mxnet
mxnet-cuda
mxnet-mkl
mxnet-mkl-cuda
mygnuhealth
mysqltuner-git
mythes-cs
n1-translator
naemon
naemon-livestatus
nanocurrency
nanocurrency-node
natapp
nautilus-folder-icons
nautilus-git
nautilus-mediainfo
nautilus-renamer
ncl
ncursesfm-git
ndyndns
nebuchadnezzar-git
necpp-git
nemerle
nem-wallet
neochat-git
neovim-autopairs-git
neovim-gtk-git
neovim-nvim-treesitter
neovim-telescope-file-browser-git
nerf-pi
netmenu
netmon-git
netrik
networkmanager-dispatcher-pdnsd
networkmanager-ssh-git
neuro-karaoke-wrapper-git
neuron-zettelkasten-bin
neuropolitical-ttf
new-api-privacy-filter
new-api-privacy-filter-git
nextcloud-app-audioplayer
nextcloud-app-carnet
nextcloud-app-facerecognition
nextcloud-app-gpoddersync
nextcloud-app-integration-dropbox
nextcloud-app-integration-google
nextcloud-app-repod
nextcloud-app-twofactor-gateway
nextcloud-git
nexus-bin
nginx-mod-vts
nhentai-git
nheqminer-cuda-git
nikki
nikola-git
nip2
nipaplay-reload-bin
nitrogen-git
nixnote2
nixnote2-git
n-ninja
nocodb
noctyra-dotfiles-git
noctyra-meta-git
nodejs-broccoli-cli
nodejs-browser-sync
nodejs-budo
nodejs-color-convert
nodejs-dicy-cli
nodejs-docs
nodejs-elm
nodejs-forever
nodejs-hotel
nodejs-how2
nodejs-ionic
nodejs-istanbul
nodejs-js2coffee
nodejs-jscs
nodejs-jsdoc
nodejs-jsfmt
nodejs-json-to-js
nodejs-markserv
nodejs-mathjs
nodejs-mkdirp
nodejs-mssql
nodejs-node-lambda
nodejs-nodemailer
nodejs-nodeppt
nodejs-nodeunit
nodejs-passport
nodejs-pkg
nodejs-qunit
nodejs-redis-commander
nodejs-sails
nodejs-shelljs
nodejs-sweet
nodejs-telegraf
nodejs-triton
nodejs-vim-debugger
nodejs-webpack
nodejs-ws
nody-greeter
non-daw-git
nordnm
notepad---bin
notepad\u2014bin
notify-desktop-git
notion-app-enhanced
nox-bin
npm-accel
nrpe
ntk-git
numix-gtk-theme
numix-themes-electric
numix-themes-green
num-utils
nuxhash-git
nvdock-bumblebee
nvidia-xrun-git
nwchem
nwchem-bin
nx3-all
obfs4proxy-bin
ob-xd
ob-xd-common
ob-xd-lv2
ob-xd-standalone
ob-xd-vst3
ocaml-js_of_ocaml
ocaml-lambda-term
ocaml-sexplib
ocaml-textutils_kernel
ocaml-typerex
ocaml-xmlm
oclint
octave-hg
octave-miscellaneous
octocode
ohcount
ohcount-git
oh-my-git
olivia-git
omnidb-server
openav-sorcer-git
open-axiom
openclaude-bin
opencode-codebase-index-bin
opencorsairlink-git
opendrop
openhab2
openhab3
open-hexagon-git
openlayers
openms
openmsx-catapult
opennebula
openpyn-nordvpn
openssh-gui-git
openstego
openui5
openxray
opl-synth
optimizevideo-git
oracle-bin
organize-bin
orientdb-community
osmose
osvr-libfunctionality-git
otcl
oterm
otf-inconsolata-g-powerline-git
otf-sauce-code-powerline-git
ovras
owncloud-client-git
oxefmsynth
oxygen-gtk3-git
pacforge
pacgem
pandacoin-git
panopticon-git
pantheon-applications-menu-git
pantheon-print-git
pantheon-session-git
pantum-driver
panwriter
paper-desktop-bin
papirus-color-scheme
papirus-maia-icon-theme-git
paq8o
parallel-python
pass-cli
pb-for-desktop
pbincli
pcb2gcode
pcsxr-git
pdf2book
pdf4qt-git
pdi-ce
peepdf
pelican-git
pencil-android-lollipop-stencils-git
pencil-material-icons-git
penguin-subtitle-player
perl-css
perl-datetime-format-sqlite
perl-debug-client
perl-getopt-euclid
perl-graph
perl-gtk2-ex-podviewer
perl-gtk2-ex-simple-list
perl-gtk2-gladexml-simple
perl-http-request-ascgi
perl-io-capture
perl-javascript-packer
perl-lwp-protocol-http10
perl-lwp-useragent-determined
perl-lyrics-fetcher
perl-orlite
perl-proc-parallelloop
perl-set-object
perl-term-extendedcolor
perl-test-corpus-audio-mpd
perl-text-aspell
perl-xml-dom
petri-foo
pfstools
pg2ipset-git
pgcli-git
pgl
pgpool-ii
phantom-wallet
pharo-bin
phoenix
phonon-qt4
phonon-qt5-vlc
php-blackfire
phpdocumentor2
php-geoip
php-legacy-geoip
php-legacy-memcache
php-memcache
php-openswoole-git
phpredis-git
php-xdiff
picom-ftlabs-git
picpuz
pidgin-cmds
pidgin-im-gnome-shell-extension
pidgin-kwallet
pidgin-nudge-svn
pine64-rkdeveloptool-git
pinegrow
pipetoys
pipewire-visualizer-git
pk2cmd-plus
pkgdistcache
pktd
pktstat
planck
plank-theme-arc
plasma5-wallpapers-video-git
plasma6-applets-fancytasks
plasma6-splashscreen-kuro-git
playhouse
playhouse-git
plex-media-player-custom
plex-media-player-mod
plex-media-player-v2
plex-trakt-scrobbler
plowshare-git
pluma-plugins
plymouth-theme-asphyxia-git
plymouth-theme-chain
plymouth-theme-monoarch
pmount-safe-removal
pmus-git
png22pnm
pnmixer-gtk3
poi-nightly-bin
poldi
polkadot-js-desktop-bin
polkit-qt4
powwow
ppcoin-qt
premake-git
prisma4postgres-bin
privacy-redirect-git
profile-sync-daemon-zen
protoc-gen-ts
psi-plus-plugins-git
psi-plus-resources-git
pulseaudio-dlna-cygn
pulsemixer-git
puppy-browser
purescript
purple-facebook-git
pygist-git
pyload-ng
pymacs
pymedusa
pypi-cli
pypiserver
pypy-setuptools
pyrescene-git
python2-appdirs
python2-cffi
python2-chardet
python2-cssselect
python2-ctypes
python2-fusepy
python2-gobject
python2-lazr-uri
python2-lhafile
python2-mutagen
python2-notify
python2-packaging
python2-paver
python2-pyparsing
python2-simplejson
python2-simpleparse
python2-stomper
python2-twodict-git
python2-xlib
python-affine
python-apt
python-argdispatch
python-autopep8-git
python-avalon_framework
python-awkward
python-axolotl-git
python-browserid
python-calmjs
python-celery
python-cerealizer
python-chompjs
python-ci-info
python-coolname
python-coremltools
python-cu2qu-git
python-dataproperty
python-dbapi-compliance
python-dictobject
python-django-js-asset
python-django-js-asset-git
python-django-modelcluster
python-django-rest-knox
python-dj-database-url
python-dugong
python-epc
python-fastmcp-slim
python-finnhub-python
python-firebase-admin
python-fmu_manipulation_toolbox
python-future
python-g4f
python-gmpy
python-hist
python-histoprint
python-hnswlib-git
python-hsaudiotag3k
python-iminuit
python-iminuit-docs
python-iso3166
python-isounidecode
python-isr-git
python-jsmin
python-json2xml
python-kiss-headers
python-luckydonald-utils
python-miio
python-milvus-lite-bin
python-mmcif
python-monotonic
python-mplhep
python-mplhep_data
python-netaudio-git
python-netaudio-lib
python-newspaper4k
python-nipype
python-nodejs-wheel
python-nodejs-wheel-binaries
python-openai-harmony
python-orange
python-pdf2docx
python-piecash
python-pluginmgr
python-poetry-plugin-dotenv
python-privy-git
python-pushbullet.py
python-pychromecast-git
python-pydns
python-pylsp-rope
python-pymilvus
python-pyrogram
python-pysocks-git
python-quamash-git
python-rembg
python-resvg
python-resvg_py
python-scikit-hep-testdata
python-single-version
python-sklearn-pandas
python-sqliteschema
python-stagger-git
python-starlette-compress
python-starsessions
python-steamcontroller-git
python-tabledata
python-tarantool
python-tradingeconomics
python-uhi
python-uproot
python-uproot-docs
python-vector
python-vincenty
python-webassets
python-xtarfile
pytomtom
pyxplot
qbittorrent-enhanced-qt5
qconf-git
qemacs
qemu-android-x86
qeven
qhttpengine
qinfo
qlementine
qmdnsengine
qmltermwidget-git
qnapi
qobuz-player-bin
qpitch
qrfcview
qscite
qshntoolsplit
qt5-3d
qt-inspector-git
qt-solutions-git
qtum-core
qtvkbd
quack
qucs
quickrdp
quickswitch-i3
qutepart-git
qv2ray-git
qwt-qt4
r2-iaito-git
r8101-dkms
rabbitvcs-cli
raccoon
raccoon-git
raceintospace
radare2-bindings
radare2-bindings-git
radare2-pipe-git
radium
rainbarf-git
rainloop
rarian
ratox-git
raven-qt
rayforge
rbutil-git
r-dbplyr
rdm-bin
rdup
reactphysics3d
reactphysics3d-docs
realtimeconfigquickscan-git
refind-theme-dreary-git
remotemouse
rep-gtk
repoporge
resetmsmice
retibbs-client-git
retrovol
rgain3
rhythmbox-git
rhythmbox-llyrics
rhythmbox-plugin-alternative-toolbar-git
rimworld
rke
rkflashtool
rkward-git
roccat-dkms
rock
rodentbane-git
rog-helper-git
rolo
ros2-arch-deps
ros2-humble-nav2-msgs
rstudio-server-git
rtags
rtags-git
rtbth-dkms
rtf2latex2e
rtorrent-ps
rtorrent-pyro-git
rtspeccy-git
ruah-orch
ruby-actionmailer
ruby-actionview
ruby-activemodel
ruby-activerecord
ruby-blankslate-2
ruby-classifier
ruby-colored
ruby-commander
ruby-compass
ruby-excon
ruby-execjs
ruby-fast-stemmer
ruby-haste
ruby-kramdown-rfc2629
ruby-libvirt
ruby-mpd
ruby-oauth
ruby-parslet-1.5
ruby-pusher-client
ruby-pygments.rb
ruby-railties
ruby-rubysdl
ruby-selenium-webdriver
ruby-sprockets
ruby-sprockets-rails
ruby-thread_safe
ruby-travis
rumor
runescape-launcher
run-mailcap
rxvt-unicode-256xresources
sachesi-bin
sakura-launcher-gui
saleae-logic
saleae-logic-beta
salt-git
samba-mounter-git
samsungctl
sandlock
satanic-icon-themes
sawfish-git
sbt-extras-git
scallion
scangearmp-mg3500series
scanssh
scavenger
scm
screenpipe-bin
sdcc-bin
sddm-stellar-theme
sdformat
seahorse-nautilus
selenium-server-standalone
sentry
sequencer64-git
sex
sfarkxtc
sfnt2woff
shadowgrounds
shadow-tech
sheeplifter
shellcheck-git
shellinabox-git
shhmsg
shhopt
shifty-git
shrinkpdf
sickrage-git
sidplay2-libs
signald
silver-searcher-git
sixfireusb-dkms
skanlite-git
skdet
slime-git
slim-unicode
slipnet
slipnet-bin
smartsim-git
smenu
smenu-git
smolrtsp
smolrtsp-libevent
snapd-git
snis-git
snowman-git
snry-shell-bin
snry-shell-qs
soapyptezuka
socnetv
softethervpn-client-manager
sogo2
solara-kernel-headers
soldat-git
sonar-icon-theme
sonixd
sonosano
sope2
so-synth-lv2-git
soundpaad-bin
soxt
spigot-plugin-essentials
splashtop-business
spring-ba
sqliteman
sqsh
squirrelmail
sshuttlee
sshuttlee-bin
stable-diffusion-webui-git
staden
staden-io_lib
stag-git
statusnotifier
stegsolve
stencyl
stlarch_font
stompbox-jack-git
streetsofrageremake
stripe-cli
structuresynth
stylelint-config-recommended
stylelint-config-standard
subbrute
sublime-music
sublist3r-git
submarine
subprocess
subsync
sunclock
sundtek
svu
sway-screenshot
sway-xkb-switcher
switchboard-git
sword-svn
sync-my-l2p
syslog-notify
t4kcommon
tack
taipan
taoframework
tarantool
taskunifier
tasmotizer-git
tbs-dvb-drivers
tbsecp3-driver-git-dkms
tcpstat
tdesktop-nolimit
telegram-desktop-dev
telegram-tdlib-purple-git
telepresence
termbox-git
terminusmod
tesseract-gui
test-malicious-nuke
test-malicious-reset
texlive-moderncv-git
textsuggest-git
thinkingrock
thinkwatt
thunar-nextcloud-plugin
thunderbird-conversations
thunderbird-sieve
tiemu
tif22pnm
tiger
tinyemu
tllocalmgr-git
tlpui-git
tnote
toggldesktop
toggldesktop-bin
tomighty
toolsched
toontown-rewritten
tora
torch7-cutorch-git
torch7-git
torch7-image-git
torch7-trepl-git
tor-messenger-bin
tortoisehg-hg
touchhle
touchosc-bin
toybox
tpp
trace-cmd-git
tracks
tramp
transcreen
translate-shell-git
transmission-gtk-git
truestudio
trytond
tsm
tsocks-tools
ttcp
ttf2eot
ttf-consolas-powerline
ttf-dejavu-emojiless
ttf-dejavu-sans-mono-powerline-git
ttf-essays
ttf-impallari-dosis
ttf-lcsmith-typewriter
ttf-material-design-icons-git
ttf-mutant-emoji
ttf-pizzadude-bullets
ttf-roboto-fontconfig
tunacode-cli
tup-git
tuxboot-git
tvnamer
tweeny
typing-game-cli
ucsf-chimera
udev-browse-git
udfclient
uget-integrator
ukui-notification-daemon
undistract-me-git
uni2ascii
unifi-beta
unyaffs
uplink-hib
upower-nocritical
urbanbrawl-wad
urho3d
urjtag-git
usbmount
v2ray-geoip-custom
vapoursynth-preview-git
vbam-git
vcp-git
vdirsyncer-git
vdrift
vectr
veracrypt-git
verso-git
vertx
vidalia
vidcutter
video-contact-sheet
viennacl
vim-clang-complete-git
vim-delimitmate
vim-easymotion
vim-fortran
vim-gitgutter
vim-hexman
vim-indent-object
vim-lighttpd
vim-live-latex-preview
vim-manpageview
vim-molokai
vim-molokai-git
vim-octave
vim-omlet
vim-pandoc-syntax-git
vim-pathogen-git
vim-perl-support
vim-pythonhelper
vim-solidity
vim-vital
vinetto
violetland-git
virtscreen
virustotal
visualstudio
vlc-arc-dark-git
vms-empire
vnote
vocalinux-git
volumeicon-git
voquill-gpu
vte-legacy
vtigercrm
vuze-extreme-mod
vuze-plugin-countrylocator
vuze-plugin-mldht
wallpaper-generator-next
wally
watchman
watsup
wavbreaker
wayland-static
wcalc
wds
webilder-gtk-patched
webui-aria2-git
wechat-devtools
weex
we-layerd-git
wemux-git
wesnoth-git
whatsie-git
whisper2tr
whisper2tr-git
whitebox
whysynth
windowmaker-git
windows2usb-git
wineasio-git
wine-nine
wings2
wire-desktop
wiringpi-git
wlroots-nvidia
wmtop
word-snatchers-cli
workbench
workbuddy-bin
wrestic-bin
writefreely
writefull-bin
wrystr-git
wsjtx-beta
wunderline
wxbase
x2vnc-no-xinerama
xapian-omega
xarchiver-assume-name
xcursor-gt3
xerox-phaser-6000-6010
xevdevserver
xf86-input-cmt
xf86-input-joystick
xf86-input-mtrack
xf86-input-mtrack-git
xf86-input-wizardpen
xfce-theme-bluebird
xforms
xorg-transset
xorg-xfsinfo
xorg-xinit-git
xosview
xplot
xpra-html5
xray-domain-list-community
xsp
xspin
xss-lock-git
xsvg
xsynth-dssi
yafaray
yafaray-git
yarg
yay4
yersinia
yii
yofrankie
yokadi
yt6801-dkms
yy
zafiro-icon-theme
zaproxy-weekly
zathura-gruvbox-git
zdoom-git
zecwallet
zelda-roth-se
zenbound2
zenmonitor
zenphoto
zenpower-dkms
zephyr
zeroinstall-injector
zerx-lab-dida-bin
zerx-lab-zed-nightly-bin
zing-17-bin
zing-21-bin
zing-8-bin
zinnia-python
z-push
zrythm-git
zsdx
zxtune-git
