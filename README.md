# AUR Security Scanner

Arch Linux has no built-in malware vetting for AUR packages, every PKGBUILD
is community-contributed and runs with your privileges. This script checks your
system for known-compromised AUR packages, suspicious PKGBUILDs, malware
persistence vectors (eBPF, systemd, temp directories), and unusual network
listeners. All checks are read-only, nothing is modified.

This project was created with assistance from AI (opencode). See the commit
history and the practical false-positive annotations in the output, those came
from testing on a real Arch system.

## Quick Start

```bash
chmod +x aur-scan.sh
./aur-scan.sh
```

Run with `--no-network` to skip the live package-list fetch and use the
embedded copy only. Run with `--help` to see full module descriptions.

## How It Works

The online reference list (1936 known-malicious AUR package names) is fetched
from the Arch Linux HedgeDoc with a 5-second timeout. If the fetch fails or
`--no-network` is set, the script falls back to the embedded plain-text list at
the bottom of this file. No data is sent anywhere.

## Modules

| # | Check | What It Does |
|---|-------|-------------|
| 1 | AUR Package Cross-Reference | Matches installed packages against the known-compromised list. The only module that produces a real `[FAIL]`. |
| 2 | Recently Installed Packages | Shows the 20 newest installs for your awareness. |
| 3 | PKGBUILD Suspicious Content | Flags risky patterns (curl\|sh, wget\|sh, chmod +x, sudo) in cached PKGBUILDs. Shelly AUR helper caches are annotated as normal. These PKGBUILDs are downloaded from AUR and legitimately use these commands. |
| 4 | npm Cache Check | Looks for known malicious npm packages (atomic-lockfile, js-digest, lockfile-js). |
| 5 | bun Cache Check | Same check in bun's package cache. |
| 6 | Temp Binaries | Lists executables in /tmp, /var/tmp, /dev/shm. Chromium crash dumps, shared-memory segments, and /tmp/aur-check/ files are annotated as normal. |
| 7 | eBPF Rootkit Check | Warns if 50+ BPF programs are loaded (requires bpftool, which is not installed by default). |
| 8 | Systemd Persistence | Flags services whose ExecStart downloads code or runs from /tmp or /dev/shm. |
| 9 | Temp Directories | Classifies hidden directories in temp space. Systemd sandboxes, X11 sockets, Wine, Steam, KDE Plasma, Node.js caches are shown as `[INFO]`. Git repos and mystery directories are `[WARN]`. |
| 10 | Network Listeners | Shows services listening on non-loopback interfaces. |

## Understanding the Output

- `[PASS]` - Everything OK, no action needed
- `[WARN]` - Caution flag. Each warning has a `[NOTE]` explaining why it's
  likely safe (e.g., "Shelly AUR helper cache, PKGBUILDs downloaded from AUR
  normally use these commands")
- `[FAIL]` - Action recommended. Currently only Module 1 produces this, meaning
  a known-compromised AUR package is installed.
- `[SKIP]` - A check could not run because an optional tool is not available
- `[INFO]` / `[NOTE]` - Information for awareness

## Dependencies

**Required:** `bash`, `pacman`, `grep`, `find`, `stat`, `date`, `ls`, `cat`. All present on a standard Arch installation.

**Optional:** `expac` (for Module 2 install dates), `bpftool` (for Module 7
eBPF check), `curl` (for live package-list fetch, skipped with `--no-network`).

**Package list:** `aur_pkg_list.txt` (sidecar file alongside the script.
Update it by fetching the latest list from the Arch Linux HedgeDoc:
`curl -sS https://md.archlinux.org/s/SxbqukK6IA/download > aur_pkg_list.txt`)

## License

GNU General Public License v3.0 or later. See the [LICENSE](LICENSE) file.
