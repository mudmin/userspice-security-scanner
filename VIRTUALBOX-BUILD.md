# VirtualBox OVA Build Plan

End-to-end recipe for building a slim VirtualBox OVA of the UserSpice Security Scanner. The output is a single `.ova` file that any Windows / macOS / Linux user can import with a double-click and have a working scanner in ~5-10 minutes.

This document is the **build playbook**. End-user installation docs are separate (and live in [HOW-IT-WORKS.md](HOW-IT-WORKS.md) once we have a download URL).

## Goal

A self-contained VirtualBox appliance:

- Ubuntu 24.04 LTS server (no GUI)
- LAMP stack (Apache + PHP 8.3 + MariaDB)
- Docker (for the scanner's containerized tools)
- The scanner cloned from GitHub
- phpMyAdmin
- Tiny File Manager
- A first-boot service that pulls Docker scanner images on the user's machine, so images are current at use time, not build time

**Target compressed size:** under 5 GB. Cloudflare R2 free tier is 10 GB stored + zero egress, so there's headroom for two versioned builds simultaneously if needed.

## Why slim, not fat

We considered pre-pulling the 4 GB of scanner Docker images during build (fat OVA). Two reasons we didn't:

1. **Pre-pulled images go stale.** Trivy's CVE database, Semgrep's registry, and PHPStan all update weekly. A 6-month-old fat OVA gives users silently outdated scan results on first run. Anyone serious will pull fresh anyway, downloading 4 GB twice.
2. **CI rebuilds are easier slim.** Nothing time-sensitive happens during the build, so the OVA can be regenerated monthly with current Ubuntu packages without needing nested Docker.

The user-facing cost is "first boot takes ~10 minutes to pull images." That's hidden behind a first-boot status page in the web UI.

---

## Prerequisites on the Windows 10 build machine

- [ ] **VirtualBox 7.x** installed ([virtualbox.org](https://www.virtualbox.org/wiki/Downloads))
- [ ] **VirtualBox Extension Pack** matching that version (for OVF export — though core export works without it; install is just nice-to-have)
- [ ] **Ubuntu 24.04 LTS server ISO** downloaded from [ubuntu.com](https://ubuntu.com/download/server) — pick the LTS, not the latest interim release
- [ ] **~30 GB free disk space** for the build (VM + intermediate OVA + compressed output)
- [ ] **zstd** for compression — get the Windows build from [github.com/facebook/zstd/releases](https://github.com/facebook/zstd/releases) or use 7-Zip with `xz` as a fallback
- [ ] **Cloudflare R2 account** with a bucket created (call it `userspice-scanner-images` or similar). API token with read+write to that bucket
- [ ] **rclone** ([rclone.org](https://rclone.org/downloads/)) for the upload, OR willingness to drag-and-drop in the R2 dashboard

---

## Quick Start (Scripted)

We have helper scripts in `virtualbox/` that automate most of the process:

```batch
REM 1. Create the VM with correct settings
virtualbox\create-vm.bat "C:\path\to\ubuntu-24.04-live-server-amd64.iso"

REM 2. Start and install Ubuntu manually (see Step 2 below for settings)
VBoxManage startvm userspice-scanner-build

REM 3. After Ubuntu install, SSH in and run the installer
ssh -p 2222 scanner@localhost
sudo -i
bash -c "$(wget -qO - https://raw.githubusercontent.com/mudmin/userspice-security-scanner/main/virtualbox/install.sh)"

REM 4. Run sysprep (cleans logs, zeros disk, shuts down)
bash -c "$(wget -qO - https://raw.githubusercontent.com/mudmin/userspice-security-scanner/main/virtualbox/sysprep.sh)"

REM 5. Export to OVA (run from Windows after VM shuts down)
virtualbox\export-ova.bat
```

Or follow the detailed manual steps below.

---

## Step 1: Create the VM in VirtualBox

**Option A: Use the script**
```batch
virtualbox\create-vm.bat "C:\path\to\ubuntu-24.04-live-server-amd64.iso"
```

**Option B: Manual** — In the VirtualBox GUI, click **New** and configure:

- [ ] **Name:** `userspice-scanner-build`
- [ ] **Type:** Linux
- [ ] **Version:** Ubuntu (64-bit)
- [ ] **Memory:** 4096 MB
- [ ] **Hard disk:** Create a new VDI, **dynamically allocated**, **20 GB** max size
  - Dynamic allocation matters — the file only grows as data is written, so the OVA stays small
- [ ] **CPU:** 2 cores (Settings → System → Processor)
- [ ] **Enable PAE/NX:** yes
- [ ] **Enable VT-x/AMD-V:** yes (System → Acceleration)
- [ ] **Network adapter 1:** NAT (default — fine for build)
- [ ] **Storage:** mount the Ubuntu 24.04 server ISO on the optical drive
- [ ] **Audio / USB:** disable (smaller OVA, fewer surprises on import)

---

## Step 2: Install Ubuntu (minimal)

Boot the VM. Walk through the installer:

- [ ] Language: English
- [ ] Keyboard: US (or whatever)
- [ ] Installation type: **Ubuntu Server** (not minimized — we need standard tools)
- [ ] Network: DHCP (NAT will give it 10.0.2.x or similar)
- [ ] Proxy: leave blank
- [ ] Mirror: defaults
- [ ] Storage: **Use entire disk**, **no LVM** (simpler imaging)
- [ ] Profile:
  - Server name: `userspice-scanner`
  - Username: `scanner`
  - Password: `scanner` (placeholder — first-boot will force change)
- [ ] Skip Ubuntu Pro
- [ ] **Install OpenSSH server: yes**
- [ ] Featured snaps: **none**
- [ ] Wait for install (~10 min). Reboot when prompted, eject ISO.

---

## Step 3: Run the headless install inside the VM

Log in as `scanner` (password `scanner`), then:

```bash
sudo -i
bash -c "$(wget -qO - https://raw.githubusercontent.com/mudmin/userspice-security-scanner/main/virtualbox/install.sh)"
```

> **Note:** `virtualbox/install.sh` does not exist yet. It needs to be written before this step — it's basically the inside-the-LXC portion of [proxmox/install-lxc.sh](proxmox/install-lxc.sh) (everything in the `CONTAINER_SCRIPT` heredoc) repackaged as a standalone script. See "Files to write before building" below.

What the script does:
- `apt update && apt upgrade`
- Install LAMP, Docker, jq, git, openssh-server, locales, etc.
- Generate `en_US.UTF-8` locale (suppresses the `LC_CTYPE` warnings the LXC build sees)
- Configure MariaDB with a placeholder password (first-boot will reset)
- Install phpMyAdmin
- Install Tiny File Manager (skipped or installed — we'll bake it in by default for the OVA, since OVA users opted into the full bundle)
- Configure Apache for the scanner
- Clone the scanner repo into `/var/www/html/userspice-security-scanner`
- Drop the PHP tuning ini (`max_execution_time=600`, `max_input_vars=10000`, etc.)
- Enable `PermitRootLogin yes` + `PasswordAuthentication yes` for SSH
- Install `/root/fixperms.sh` and `/root/fixdb.sh`
- Drop `/var/www/html/index.php` redirect
- **Do NOT pre-pull Docker images** (that's the slim part — first-boot does it)
- **Do NOT set final passwords** (first-boot prompts for them)

---

## Step 4: Set up the first-boot flow

The first-boot service is what makes the slim OVA usable: it pulls Docker images, prompts the user for passwords, and flips a flag so the web UI knows when to switch from "setting up..." to the real dashboard.

Write three files inside the VM (these will eventually live in `virtualbox/` in the repo):

### `/etc/systemd/system/userspice-firstboot.service`

```ini
[Unit]
Description=UserSpice Scanner first-boot setup
After=network-online.target docker.service
Wants=network-online.target
ConditionPathExists=!/var/lib/userspice-firstboot.done

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/userspice-firstboot.sh
RemainAfterExit=yes
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
```

### `/usr/local/sbin/userspice-firstboot.sh`

Pseudocode — actual script TBD:

```bash
#!/usr/bin/env bash
set -uo pipefail
FLAG=/var/lib/userspice-firstboot.done

# 1. Generate fresh passwords (or read from a kernel cmdline / cloud-init file if user pre-seeded)
ROOT_PW=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-16)
MYSQL_PW=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-16)

# 2. Set system passwords
echo "root:$ROOT_PW" | chpasswd
echo "scanner:$ROOT_PW" | chpasswd

# 3. Reset MariaDB root password and rewrite /root/.my.cnf, phpMyAdmin's debconf, TFM config

# 4. Pull Docker images (the actual work — the bit users wait for)
source /var/www/html/userspice-security-scanner/lib/common.sh
for img in "$SEMGREP_IMAGE" "$PSALM_IMAGE" "$TRIVY_IMAGE" "$GITLEAKS_IMAGE" "$PHPSTAN_IMAGE" "$ZAP_IMAGE"; do
    docker pull "$img"
done

# 5. Write a credentials file that the web UI reads to display the passwords once
cat > /var/www/html/userspice-security-scanner/.firstboot-credentials.json <<EOF
{"root_pw": "$ROOT_PW", "mysql_pw": "$MYSQL_PW", "shown": false}
EOF
chown www-data:www-data /var/www/html/userspice-security-scanner/.firstboot-credentials.json
chmod 640 /var/www/html/userspice-security-scanner/.firstboot-credentials.json

# 6. Mark done
touch "$FLAG"
```

### Web UI changes (small)

Add a check in [ui/index.php](ui/index.php) above the auth gate: if `/var/lib/userspice-firstboot.done` doesn't exist, render a "Setting up scanners — about 5 minutes. The page will refresh." page with a meta refresh tag. Once the flag exists and `.firstboot-credentials.json` has `shown: false`, render a one-time credentials display, then mark `shown: true` so it never reappears.

> This is the trickiest part of the build. It's worth getting right because it's the user's first impression. We can keep it dumb-simple for v1: just a "please wait" page with no credential display, and tell users in the docs to run `cat /var/lib/userspice-firstboot-creds.txt` over SSH to get their passwords. Decide before building.

Enable the service:

```bash
systemctl daemon-reload
systemctl enable userspice-firstboot.service
```

---

## Step 5: Configure VirtualBox port forwarding (in the OVA metadata)

End users won't know to open a port forward. Bake one in so `http://localhost:8080` on the host hits the VM's port 80:

```bash
# On the Windows host, BEFORE export:
VBoxManage modifyvm userspice-scanner-build --natpf1 "http,tcp,,8080,,80"
VBoxManage modifyvm userspice-scanner-build --natpf1 "ssh,tcp,,2222,,22"
```

These rules travel with the OVA. End users can change them in VirtualBox Settings → Network → Advanced → Port Forwarding.

---

## Step 6: Sysprep (clean the VM before export)

Inside the VM as root:

```bash
# Clear shell history
history -c
rm -f /root/.bash_history /home/scanner/.bash_history
unset HISTFILE

# Clear logs (optional but shrinks the image)
journalctl --rotate
journalctl --vacuum-time=1s
find /var/log -type f -exec truncate -s 0 {} \;

# Reset machine-id so each booted clone gets a unique one
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

# Remove SSH host keys — regenerated on first boot by openssh-server
rm -f /etc/ssh/ssh_host_*

# Clear apt cache
apt-get clean
rm -rf /var/lib/apt/lists/*

# Zero out free space — makes compression dramatically more effective
dd if=/dev/zero of=/zerofile bs=1M status=progress || true
rm -f /zerofile
sync

# Shut down cleanly
shutdown -h now
```

---

## Step 7: Compact the VDI

After the VM is shut down, on the Windows host:

```bash
VBoxManage modifyhd "C:\path\to\userspice-scanner-build.vdi" --compact
```

This reclaims the zeroed-out space. Skipping this step roughly doubles the OVA size.

---

## Step 8: Export to OVA

```bash
VBoxManage export userspice-scanner-build ^
    -o userspice-scanner-v0.X.0.ova ^
    --ovf20 ^
    --vsys 0 ^
    --product "UserSpice Security Scanner" ^
    --producturl "https://github.com/mudmin/userspice-security-scanner" ^
    --vendor "mudmin" ^
    --version "0.X.0" ^
    --description "Local security scanner for UserSpice projects. First boot takes ~10 min to pull scanner images."
```

(Replace `0.X.0` with the current contents of [VERSION](VERSION).)

---

## Step 9: Compress

```bash
zstd --ultra -22 -T0 userspice-scanner-v0.X.0.ova
# or, if zstd not available:
xz -9e -T0 userspice-scanner-v0.X.0.ova
```

Expected output: ~3-4 GB. If it lands above 6 GB, something's wrong (probably skipped Step 6 zero-fill or Step 7 compact).

If we ever need to slim further, the next lever is "don't pre-install phpMyAdmin or Tiny File Manager — let first-boot install them." Saves ~200 MB. Don't bother unless we hit a real ceiling.

---

## Step 10: Upload to Cloudflare R2

Either via rclone:

```bash
rclone config  # one-time: add an R2 remote with API token
rclone copy userspice-scanner-v0.X.0.ova.zst r2:userspice-scanner-images/
```

Or via the R2 web dashboard (drag & drop). Either way:

- [ ] Make the bucket / object public, or set up a custom domain pointing at it
- [ ] Note the public URL (will look like `https://pub-XXXX.r2.dev/userspice-scanner-images/userspice-scanner-v0.X.0.ova.zst` or your custom domain)
- [ ] Add the URL to [HOW-IT-WORKS.md](HOW-IT-WORKS.md) under a new "Option C — VirtualBox" section

---

## Files included in virtualbox/

These files are ready to use:

| File | Purpose |
|------|---------|
| `virtualbox/install.sh` | Headless installer — LAMP, Docker, phpMyAdmin, TFM, scanner, first-boot service. Run with `sudo bash install.sh` on a fresh Ubuntu 24 server VM. |
| `virtualbox/firstboot.sh` | First-boot script — generates passwords, pulls Docker images, writes credentials. Installed to `/usr/local/sbin/userspice-firstboot.sh` by install.sh. |
| `virtualbox/userspice-firstboot.service` | Systemd unit — runs firstboot.sh once on first boot. |
| `virtualbox/sysprep.sh` | Pre-export cleanup — clears logs, zeros disk, shuts down. Run before exporting OVA. |
| `virtualbox/create-vm.bat` | Windows script — creates VM with correct settings, attaches ISO. |
| `virtualbox/export-ova.bat` | Windows script — compacts VDI, exports to OVA with metadata. |

The `ui/index.php` first-boot gate is already implemented — it shows a "Setting up..." spinner while first-boot runs, then displays credentials once.

---

## Open decisions

- **Default user inside the VM** — keep `scanner` (Ubuntu install creates it), or rename to `ubuntu`? Right now I assume `scanner`.
- **First-boot password display** — show in web UI on first visit (slick, more code), or write to `/var/lib/userspice-firstboot-creds.txt` and tell users to SSH in and `cat` it (boring, less code, more reliable)? Slim case for v1: pick the boring option.
- **Should the VM auto-`apt upgrade` on first boot?** Pro: users always get current security patches. Con: adds 5-10 minutes to first-boot, can fail in unusual ways. Default: no — let users do it manually if they care, document in HOW-IT-WORKS.
- **OVF version: 2.0 or 1.0?** OVF 2.0 is the modern default. Some older VirtualBox versions (pre-6.0) don't accept it, but those are 5+ years old. Stick with 2.0.
- **Versioning the filename** vs symlinking `latest` — recommend versioning explicitly so users can pin to a known-working build, and adding a `latest.txt` file in R2 that contains the current filename for auto-detect tooling later.

---

## What's NOT in this plan

- Vagrant box generation (different format, different audience)
- Hyper-V VHD (different format, smaller user base)
- WSL2 tarball (different paradigm, technical-user-only)
- VMware OVA — VirtualBox-exported OVA imports into VMware Workstation 16+ correctly without changes, so we get this for free
- Code signing the OVA — possible but requires a signing cert, $$. Skip for v1.

If any of the above become priorities, they're separate plan documents.
