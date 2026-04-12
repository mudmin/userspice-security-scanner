#!/usr/bin/env bash
# ============================================================================
# UserSpice Security Scanner — Proxmox LXC Installer
#
# Creates an unprivileged Ubuntu 24.04 LXC on a Proxmox VE host, installs
# Apache + PHP + MariaDB + Docker, and clones + configures the scanner.
#
# Run on a Proxmox host as root:
#
#   bash -c "$(wget -qO - https://raw.githubusercontent.com/mudmin/userspice-security-scanner/main/proxmox/install-lxc.sh)"
#
# Or locally:
#
#   wget -qO install-lxc.sh https://raw.githubusercontent.com/mudmin/userspice-security-scanner/main/proxmox/install-lxc.sh
#   bash install-lxc.sh
# ============================================================================

set -uo pipefail

REPO_URL="https://github.com/mudmin/userspice-security-scanner.git"
REPO_DIR_NAME="userspice-security-scanner"
APP_NAME="UserSpice Security Scanner"

DEFAULT_HOSTNAME="userspice-scanner"
DEFAULT_DISK="16"      # GB — Docker images ~4GB + reports + OS
DEFAULT_CORES="2"
DEFAULT_RAM="4096"     # MB — Semgrep/PHPStan can be memory-hungry
DEFAULT_SWAP="512"
DEFAULT_BRIDGE="vmbr0"
DEFAULT_TEMPLATE_STORAGE="local"
DEFAULT_CT_STORAGE="local-lvm"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
fail() { echo -e "  ${RED}[X]${NC} $*" >&2; }
info() { echo -e "  ${BLUE}[i]${NC} $*"; }
ask()  { echo -en "  ${CYAN}[?]${NC} $* "; }
step() { echo -e "\n${BOLD}${CYAN}==>${NC} ${BOLD}$*${NC}"; }

# ---- Preconditions ----
if ! command -v pct &>/dev/null; then
    fail "This script must run on a Proxmox VE host (pct not found)."
    exit 1
fi
if [[ $EUID -ne 0 ]]; then
    fail "This script must run as root."
    exit 1
fi

clear
echo ""
echo -e "${BOLD}${CYAN}${APP_NAME}${NC}"
echo -e "${BOLD}${CYAN}Proxmox LXC Installer${NC}"
echo ""
echo "Creates an unprivileged Ubuntu 24.04 LXC with:"
echo "  - Apache + PHP 8.3 + MariaDB (LAMP)"
echo "  - Docker (for the scanner's containerized tools)"
echo "  - The scanner cloned to /var/www/html/${REPO_DIR_NAME}"
echo ""

# ---- Gather input ----
step "Configuration"

NEXT_ID=$(pvesh get /cluster/nextid 2>/dev/null || echo "200")
ask "Container ID [${NEXT_ID}]:"
read -r CTID
CTID="${CTID:-$NEXT_ID}"

if pct status "$CTID" &>/dev/null; then
    fail "Container ${CTID} already exists. Pick a different ID or destroy it first."
    exit 1
fi

ask "Hostname [${DEFAULT_HOSTNAME}]:"
read -r HOSTNAME
HOSTNAME="${HOSTNAME:-$DEFAULT_HOSTNAME}"

ask "Disk size in GB [${DEFAULT_DISK}]:"
read -r DISK
DISK="${DISK:-$DEFAULT_DISK}"

ask "CPU cores [${DEFAULT_CORES}]:"
read -r CORES
CORES="${CORES:-$DEFAULT_CORES}"

ask "RAM in MB [${DEFAULT_RAM}]:"
read -r RAM
RAM="${RAM:-$DEFAULT_RAM}"

ask "Network bridge [${DEFAULT_BRIDGE}]:"
read -r BRIDGE
BRIDGE="${BRIDGE:-$DEFAULT_BRIDGE}"

ask "Template storage [${DEFAULT_TEMPLATE_STORAGE}]:"
read -r TEMPLATE_STORAGE
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-$DEFAULT_TEMPLATE_STORAGE}"

ask "Container storage [${DEFAULT_CT_STORAGE}]:"
read -r CT_STORAGE
CT_STORAGE="${CT_STORAGE:-$DEFAULT_CT_STORAGE}"

ask "Root password (leave empty to generate):"
read -rs ROOT_PW
echo ""
GENERATED_PW=0
gen_pw() {
    if command -v openssl &>/dev/null; then
        openssl rand -base64 18 | tr -d '/+=' | cut -c1-16
    else
        tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
    fi
}
if [[ -z "$ROOT_PW" ]]; then
    ROOT_PW="$(gen_pw)"
    GENERATED_PW=1
fi
# Always auto-generate the MariaDB root password — no reason to make the user pick one.
MYSQL_PW="$(gen_pw)"

echo ""
echo -e "${BOLD}Review:${NC}"
echo "  CTID:            ${CTID}"
echo "  Hostname:        ${HOSTNAME}"
echo "  Disk:            ${DISK} GB on ${CT_STORAGE}"
echo "  CPU / RAM:       ${CORES} cores / ${RAM} MB"
echo "  Bridge:          ${BRIDGE}"
echo "  Template store:  ${TEMPLATE_STORAGE}"
echo ""
ask "Proceed? [Y/n]:"
read -r CONFIRM
if [[ "${CONFIRM,,}" == "n" ]]; then
    info "Cancelled."
    exit 0
fi

# ---- Template ----
step "Finding Ubuntu 24.04 template"
pveam update >/dev/null 2>&1 || warn "pveam update failed (continuing)"

LATEST_TEMPLATE=$(pveam available --section system 2>/dev/null \
    | awk '/ubuntu-24\.04-standard/ {print $2}' \
    | sort -V | tail -1)

if [[ -z "$LATEST_TEMPLATE" ]]; then
    fail "No Ubuntu 24.04 template available via pveam."
    fail "Check: pveam available --section system | grep ubuntu-24"
    exit 1
fi
info "Latest available: ${LATEST_TEMPLATE}"

if ! pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep -q "${LATEST_TEMPLATE}"; then
    info "Not in storage — downloading..."
    if ! pveam download "$TEMPLATE_STORAGE" "$LATEST_TEMPLATE"; then
        fail "Template download failed."
        exit 1
    fi
fi
TEMPLATE_PATH="${TEMPLATE_STORAGE}:vztmpl/${LATEST_TEMPLATE}"
ok "Template: ${LATEST_TEMPLATE}"

# ---- Create container ----
step "Creating LXC ${CTID}"
if ! pct create "$CTID" "$TEMPLATE_PATH" \
        --hostname "$HOSTNAME" \
        --cores "$CORES" \
        --memory "$RAM" \
        --swap "$DEFAULT_SWAP" \
        --rootfs "${CT_STORAGE}:${DISK}" \
        --net0 "name=eth0,bridge=${BRIDGE},firewall=1,ip=dhcp,ip6=auto" \
        --features "nesting=1,keyctl=1,fuse=1" \
        --unprivileged 1 \
        --onboot 1 \
        --password "$ROOT_PW" \
        --ostype ubuntu \
        --description "${APP_NAME}"; then
    fail "pct create failed."
    exit 1
fi
ok "Container ${CTID} created"

cleanup_on_fail() {
    warn "Install failed — cleaning up container ${CTID}"
    pct stop "$CTID" &>/dev/null || true
    pct destroy "$CTID" &>/dev/null || true
}

# ---- Start + wait for network ----
step "Starting container"
pct start "$CTID"

NETWORK_READY=0
for i in {1..30}; do
    if pct exec "$CTID" -- bash -c 'getent hosts github.com &>/dev/null' 2>/dev/null; then
        NETWORK_READY=1
        break
    fi
    sleep 1
done
if [[ $NETWORK_READY -eq 0 ]]; then
    cleanup_on_fail
    fail "Container has no DNS/network after 30s. Check ${BRIDGE} and DHCP."
    exit 1
fi
ok "Network up"

# ---- Install LAMP + Docker + tooling + LXC helpers ----
step "Installing LAMP, Docker, phpMyAdmin, and LXC helpers (several minutes)"

# We use heredoc-on-stdin (not bash -c '...') so the user's helper scripts —
# which contain single quotes in things like RED='\033[0;31m' — flow through
# verbatim without escape hell. The outer terminator is quoted ('CONTAINER_SCRIPT')
# so the host does no interpolation; MYSQL_PW reaches the container via env.
INSTALL_RC=0
pct exec "$CTID" -- env MYSQL_PW="$MYSQL_PW" bash <<'CONTAINER_SCRIPT' || INSTALL_RC=$?
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get upgrade -yq

# LAMP + Docker + tooling
apt-get install -yq --no-install-recommends apache2 mariadb-server php php-cli php-mysql php-xml php-mbstring php-curl php-zip php-gd php-intl libapache2-mod-php docker.io jq git curl unzip openssh-server sudo ca-certificates openssl

systemctl enable --now docker
systemctl enable --now apache2
systemctl enable --now mariadb
systemctl enable --now ssh

# Allow root password login over SSH so SFTP/SCP work for transferring projects in.
# Ubuntu 24 ships with PermitRootLogin prohibit-password, which blocks SFTP/SCP entirely.
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-userspice-scanner.conf <<SSHCFG
PermitRootLogin yes
PasswordAuthentication yes
SSHCFG
systemctl restart ssh

# webdev group convention — used by /root/fixperms.sh on user-loaded projects.
# Created here so the helper script has a working baseline; the scanner repo
# itself stays owned by www-data:www-data and is NOT touched by this group.
groupadd -f webdev
usermod -aG webdev www-data

# Set MariaDB root password (chained auth: sudo mysql still works AND password auth works for phpMyAdmin)
mariadb <<SQL
ALTER USER "root"@"localhost" IDENTIFIED VIA unix_socket OR mysql_native_password USING PASSWORD("$MYSQL_PW");
FLUSH PRIVILEGES;
SQL

cat > /root/.my.cnf <<CNF
[client]
user=root
password=$MYSQL_PW
CNF
chmod 600 /root/.my.cnf

# phpMyAdmin (non-interactive via debconf)
debconf-set-selections <<DEBCONF
phpmyadmin phpmyadmin/dbconfig-install boolean true
phpmyadmin phpmyadmin/app-password-confirm password $MYSQL_PW
phpmyadmin phpmyadmin/mysql/admin-pass password $MYSQL_PW
phpmyadmin phpmyadmin/mysql/app-pass password $MYSQL_PW
phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2
DEBCONF
apt-get install -yq phpmyadmin

# /var/www/html landing page — redirect to the scanner UI
rm -f /var/www/html/index.html
cat > /var/www/html/index.php <<INDEXPHP
<?php
header('Location: /userspice-security-scanner/ui/');
exit;
INDEXPHP
chown www-data:www-data /var/www/html/index.php

# /root/fixperms.sh — fix permissions for a project dir under /var/www/html
cat > /root/fixperms.sh <<"FIXPERMS_END"
#!/bin/bash

# fixperms.sh - Fix web directory permissions for UserSpice/web apps
# Usage: ./fixperms.sh [directory_name|*]
# Example: ./fixperms.sh plgdev
# Example: ./fixperms.sh *

# Configuration - adjust these if needed
WEB_ROOT="/var/www/html"
WEB_USER="www-data"
WEB_GROUP="webdev"
CURRENT_USER=$(whoami)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to fix permissions for a single directory
fix_directory_perms() {
    local target_dir="$1"
    local full_path="$WEB_ROOT/$target_dir"

    if [ ! -d "$full_path" ]; then
        print_error "Directory $full_path does not exist"
        return 1
    fi

    print_status "Fixing permissions for: $full_path"

    # Set ownership to current user and webdev group
    print_status "Setting ownership to $CURRENT_USER:$WEB_GROUP"
    sudo chown -R "$WEB_USER:$WEB_GROUP" "$full_path"
    	# save this old way of doing it
	# sudo chown -R "$CURRENT_USER:$WEB_GROUP" "$full_path"

    # Set directory permissions (755 + group write = 775)
    print_status "Setting directory permissions to 775"
    sudo find "$full_path" -type d -exec chmod 775 {} \;

    # Set file permissions (644 + group write = 664)
    print_status "Setting file permissions to 755"
    sudo find "$full_path" -type f -exec chmod 775 {} \;

    # Make PHP files executable
    print_status "Making PHP files executable"
    sudo find "$full_path" -name "*.php" -exec chmod 775 {} \;

    # Set the setgid bit on directories so new files inherit the group
    print_status "Setting setgid bit on directories"
    sudo find "$full_path" -type d -exec chmod g+s {} \;

    print_status "Completed: $target_dir"
    echo ""
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_error "Don't run this script as root. Run as your regular user - it will use sudo when needed."
    exit 1
fi

# Check if webdev group exists
if ! getent group "$WEB_GROUP" > /dev/null 2>&1; then
    print_error "Group '$WEB_GROUP' does not exist. Please create it first:"
    echo "  sudo groupadd $WEB_GROUP"
    echo "  sudo usermod -a -G $WEB_GROUP $CURRENT_USER"
    echo "  sudo usermod -a -G $WEB_GROUP $WEB_USER"
    exit 1
fi

# Check if user is in webdev group
if ! groups "$CURRENT_USER" | grep -q "$WEB_GROUP"; then
    print_error "User '$CURRENT_USER' is not in group '$WEB_GROUP'"
    echo "Run: sudo usermod -a -G $WEB_GROUP $CURRENT_USER"
    echo "Then log out and back in."
    exit 1
fi

# Check if www-data is in webdev group
if ! groups "$WEB_USER" | grep -q "$WEB_GROUP"; then
    print_error "User '$WEB_USER' is not in group '$WEB_GROUP'"
    echo "Run: sudo usermod -a -G $WEB_GROUP $WEB_USER"
    exit 1
fi

# Main logic
if [ $# -eq 0 ]; then
    print_error "Usage: $0 [directory_name|*]"
    echo "Examples:"
    echo "  $0 plgdev"
    echo "  $0 '*'"
    exit 1
fi

cd "$WEB_ROOT" || exit 1

if [ "$1" = "*" ]; then
    print_status "Fixing permissions for ALL directories in $WEB_ROOT"
    print_warning "This will take a while..."

    for dir in */; do
        if [ -d "$dir" ]; then
            fix_directory_perms "${dir%/}"
        fi
    done
else
    fix_directory_perms "$1"
fi

print_status "Permission fixing complete!"
print_status "Both you ($CURRENT_USER) and the web server ($WEB_USER) should now have full access."

# Test if we can create a file as www-data
if [ "$1" != "*" ]; then
    test_file="$WEB_ROOT/$1/perm_test_$(date +%s).tmp"
    if sudo -u "$WEB_USER" touch "$test_file" 2>/dev/null; then
        sudo rm "$test_file"
        print_status "Permission test passed - www-data can write to $1"
    else
        print_error "Permission test failed - www-data cannot write to $1"
    fi
fi
FIXPERMS_END
chmod +x /root/fixperms.sh

# /root/fixdb.sh — replace utf8mb4_0900_ai_ci with utf8mb4_unicode_ci in a SQL dump
cat > /root/fixdb.sh <<"FIXDB_END"
#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <dumpfile.sql>"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo "File not found: $1"
    exit 1
fi

sed -i 's/utf8mb4_0900_ai_ci/utf8mb4_unicode_ci/g' "$1"
echo "Done. Replaced all utf8mb4_0900_ai_ci with utf8mb4_unicode_ci in $1"
FIXDB_END
chmod +x /root/fixdb.sh

systemctl restart apache2
CONTAINER_SCRIPT

if [[ $INSTALL_RC -ne 0 ]]; then
    cleanup_on_fail
    fail "Package install failed."
    exit 1
fi
ok "Packages installed, MariaDB configured, helpers in /root/"

# ---- Clone scanner + wire it up ----
step "Cloning scanner repo"
if ! pct exec "$CTID" -- bash -c "
set -e
cd /var/www/html
git clone '$REPO_URL' '$REPO_DIR_NAME'
chown -R www-data:www-data '/var/www/html/${REPO_DIR_NAME}'
usermod -aG docker www-data
cd '/var/www/html/${REPO_DIR_NAME}'
cat > scanner.conf <<EOF
# UserSpice Security Scanner — Local Configuration
# Generated by proxmox/install-lxc.sh
BASE_SCAN_DIR=/var/www/html
EOF
chown www-data:www-data scanner.conf
chmod g+ws reports 2>/dev/null || mkdir -p reports && chown www-data:www-data reports && chmod g+ws reports
"; then
    cleanup_on_fail
    fail "Scanner clone / configure failed."
    exit 1
fi
ok "Scanner configured"

# ---- Pre-pull Docker images ----
step "Pre-pulling scanner Docker images (~4GB, several minutes)"
pct exec "$CTID" -- bash -c '
set -e
source /var/www/html/'"$REPO_DIR_NAME"'/lib/common.sh
for img in "$SEMGREP_IMAGE" "$PSALM_IMAGE" "$TRIVY_IMAGE" "$GITLEAKS_IMAGE" "$PHPSTAN_IMAGE" "$ZAP_IMAGE"; do
    echo "  pulling $img"
    docker pull "$img" >/dev/null
done
' || warn "Image pull had errors — run ./scan.sh --pull inside the container to retry"
ok "Images ready"

# ---- Restart apache so www-data picks up docker group ----
pct exec "$CTID" -- systemctl restart apache2 >/dev/null 2>&1 || true

# ---- Summary ----
CT_IP=$(pct exec "$CTID" -- bash -c "hostname -I | awk '{print \$1}'" 2>/dev/null | tr -d '[:space:]')

echo ""
echo -e "${BOLD}${GREEN}========================================${NC}"
echo -e "${BOLD}${GREEN}  Installation complete${NC}"
echo -e "${BOLD}${GREEN}========================================${NC}"
echo ""
echo -e "  Container ID:   ${BOLD}${CTID}${NC}"
echo -e "  Hostname:       ${BOLD}${HOSTNAME}${NC}"
echo -e "  IP:             ${BOLD}${CT_IP:-<not-detected>}${NC}"
if [[ $GENERATED_PW -eq 1 ]]; then
    echo -e "  Root password:  ${BOLD}${ROOT_PW}${NC}   ${YELLOW}(LXC root login — generated)${NC}"
else
    echo -e "  Root password:  ${BOLD}<as entered>${NC}"
fi
echo -e "  MariaDB root:   ${BOLD}${MYSQL_PW}${NC}   ${YELLOW}(database root — generated)${NC}"
echo ""
echo -e "  Web UI:      ${BOLD}http://${CT_IP:-<ip>}/${NC}   (auto-redirects to /${REPO_DIR_NAME}/ui/)"
echo -e "  phpMyAdmin:  ${BOLD}http://${CT_IP:-<ip>}/phpmyadmin/${NC}"
echo -e "  SSH/SFTP:    ${BOLD}ssh root@${CT_IP:-<ip>}${NC}"
echo -e "  Console:     ${BOLD}pct enter ${CTID}${NC}"
echo ""
echo -e "  ${YELLOW}Save both passwords now — they will not be shown again.${NC}"
echo "  (MariaDB password is also stored in /root/.my.cnf inside the container)"
echo ""
echo -e "  ${BOLD}Helper scripts in /root/ (LXC only):${NC}"
echo "    fixperms.sh   — chown -R www-data:webdev + 775 + setgid for a project dir"
echo "                    Refuses to run as root by design — create a regular user first:"
echo "                      useradd -m -G webdev,sudo,docker -s /bin/bash <name>"
echo "                      passwd <name>"
echo "    fixdb.sh      — sed-replace utf8mb4_0900_ai_ci -> utf8mb4_unicode_ci in a SQL dump"
echo ""
echo "  The 'webdev' group exists and www-data is in it. The scanner repo itself is"
echo "  owned by www-data:www-data and is not touched by fixperms.sh — only run"
echo "  fixperms.sh against your loaded project directories, not the scanner."
echo ""
echo -e "  ${BOLD}Loading a project to scan:${NC}"
echo "    1. Create a database for the project in phpMyAdmin"
echo "    2. Copy project files into /var/www/html/<projectname>/ in the container"
echo "         pct push ${CTID} myproject.tar.gz /root/myproject.tar.gz"
echo "         pct exec ${CTID} -- tar -xzf /root/myproject.tar.gz -C /var/www/html/"
echo "    3. Edit users/init.php with your DB credentials so the project actually runs"
echo -e "       ${YELLOW}REQUIRED for authenticated/active ZAP scanning — the auth bootstrap${NC}"
echo -e "       ${YELLOW}can only log in if the project is fully configured.${NC}"
echo "    4. Open the Web UI and click the project, or run:"
echo "         pct exec ${CTID} -- bash -c 'cd /var/www/html/${REPO_DIR_NAME} && ./scan.sh <projectname>'"
echo ""
