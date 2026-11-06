#!/bin/bash
# freeradius-woofweb installer for a clean Debian 13 host (services and paths are named radius-manager). Running it again upgrades the
# program files and keeps every setting, secret and upload.
#
#   wget -O install.sh https://raw.githubusercontent.com/liao-chianan/freeradius-woofweb/main/install.sh && sudo bash install.sh
#   (recommended: a failed download is reported and nothing runs; piping "wget -qO- ... | sudo bash" also works,
#    but a failed download then exits silently)
#   sudo bash install.sh --source /path/to/checkout    install from a local copy
#   sudo bash install.sh --version v1.2.3              install a specific release
#   sudo bash install.sh --port 8443                    web interface port (default 3333; asked on first install)
# The web interface lives under /woofradius/; any other path returns 404.
# Every step is shown on the console and appended to /var/log/radius-manager-install.log (the one-time setup link is not logged).
set -Eeuo pipefail

# Shown first, before anything can fail: no output at all means this script never reached bash (the download failed).
printf '==> freeradius-woofweb installer started (%s, user %s, host %s)\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$(id -un)" "$(hostname)"

# Set this once the repository exists; it is the only place the location is defined.
REPO="${RADMGR_REPO:-liao-chianan/freeradius-woofweb}"
VERSION="main"
SOURCE=""
PORT="${RADMGR_PORT:-}"
BASE=/opt/radius-manager
WEB_ENV=/etc/radius-manager/web.env
DEFAULT_PORT=3333
URL_PREFIX=/woofradius
LOG=/var/log/radius-manager-install.log
STEP=0
STARTED=$(date +%s)

die() {
  printf '\nERROR: %s\n' "$*" >&2
  [ -n "${LOGGING:-}" ] && printf 'The full output of this run is in %s\n' "$LOG" >&2
  exit 1
}
step() { STEP=$((STEP + 1)); printf '\n==> [%d] %s\n' "$STEP" "$*"; }
info() { printf '    %s\n' "$*"; }
# set -e stops the script on any failed command; say which one instead of exiting silently.
on_error() {
  local code=$1 line=$2 cmd=$3
  # A failure inside $(...) is handled by the command that uses it; only the main script reports.
  [ "$BASHPID" = "$$" ] || exit "$code"
  printf '\nERROR: the installer stopped: a command failed (exit code %s) at install.sh line %s:\n    %s\n' "$code" "$line" "$cmd" >&2
  [ -n "${LOGGING:-}" ] && printf 'The full output of this run is in %s\n' "$LOG" >&2
  exit "$code"
}
trap 'on_error $? $LINENO "$BASH_COMMAND"' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --source) [ $# -ge 2 ] || die "--source needs a directory"; SOURCE="$2"; shift 2 ;;
    --version) [ $# -ge 2 ] || die "--version needs a tag such as v0.8.3"; VERSION="$2"; shift 2 ;;
    --port) [ $# -ge 2 ] || die "--port needs a number"; PORT="$2"; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "run as root, for example with sudo"

# From here on everything also goes to the log. fd 3/4 keep the console for the end (the one-time setup link is not logged).
exec 3>&1 4>&2
touch "$LOG" && chmod 600 "$LOG"
exec > >(tee -a "$LOG") 2>&1
TEE_PID=$!
LOGGING=1
# Close the log pipe and wait for tee, so its last lines are not printed after the shell prompt.
finish_log() {
  if [ -n "${LOGGING:-}" ]; then
    LOGGING=""
    exec 1>&3 2>&4
    wait "$TEE_PID" 2>/dev/null || true
  fi
}
cleanup() { if [ -n "${WORK:-}" ]; then rm -rf "$WORK"; fi; finish_log; }
trap cleanup EXIT
printf '\n========== %s install.sh %s ==========\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"
info "log file: $LOG"

step "Checking this host"
# Read os-release in a subshell: it defines VERSION, NAME and others that would overwrite this script's variables
# (VERSION="13 (trixie)" replaced the release to download).
OS_INFO=$(. /etc/os-release 2>/dev/null; printf '%s|%s|%s' "${ID:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-unknown}")
IFS='|' read -r OS_ID OS_VERSION_ID OS_PRETTY <<< "$OS_INFO"
info "system: $OS_PRETTY ($(uname -m), kernel $(uname -r))"
[ "$OS_ID" = debian ] && [ "$OS_VERSION_ID" = 13 ] || die "only Debian 13 is supported (found $OS_PRETTY)"
command -v systemctl >/dev/null || die "systemd is required"
info "systemd: $(systemctl --version 2>/dev/null | sed -n 1p)"
VIRT=$(systemd-detect-virt 2>/dev/null || true)
info "virtualization: ${VIRT:-none}"
IP=$(ip -4 route get 192.0.2.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p;q' || true)
info "IPv4 address: ${IP:-not found}"
info "DNS servers: $(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)"
if [ -e "$BASE/current" ]; then
  info "installed version: $(cat "$BASE/current/VERSION" 2>/dev/null || echo unknown) (this run upgrades it and keeps the settings)"
else
  info "installed version: none (new install)"
fi

# ---- web interface port ----
step "Choosing the web interface port"
port_ok() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] || { echo "    the port must be a number"; return 1; }
  [ "$1" -ge 1024 ] && [ "$1" -le 65535 ] || { echo "    the port must be 1024-65535 (the service runs without privileges)"; return 1; }
  case "$1" in 1812|1813|18120) echo "    port $1 is used by FreeRADIUS"; return 1 ;; esac
  # A port held by radius-manager itself (an upgrade, or moving back) is fine.
  local main; main=$(systemctl show -p MainPID --value radius-manager 2>/dev/null || echo 0)
  if ss -Hltnp "sport = :$1" 2>/dev/null | grep -v "pid=${main:-0}," | grep -q .; then
    echo "    port $1 is already in use on this host"; return 1
  fi
}
EXISTING_PORT=$(sed -n 's/^FLASK_RADIUS_PORT=//p' "$WEB_ENV" 2>/dev/null || true)
# Installed before the port became selectable: it has always been 3333.
if [ -z "$EXISTING_PORT" ] && [ -f /etc/radius-manager/env ]; then EXISTING_PORT=$DEFAULT_PORT; fi
if [ -n "$PORT" ]; then
  port_ok "$PORT" || die "invalid --port $PORT"
  info "port $PORT (from --port)"
elif [ -n "$EXISTING_PORT" ]; then
  PORT="$EXISTING_PORT"                     # upgrade: keep the port chosen before
  info "port $PORT (kept from the existing installation)"
elif [ -r /dev/tty ] && [ -w /dev/tty ] && { : < /dev/tty; } 2>/dev/null; then
  # stdin is the downloaded script when run as "wget ... | sudo bash", so ask on the terminal
  while :; do
    printf 'Web interface port [%s]: ' "$DEFAULT_PORT" > /dev/tty
    IFS= read -r PORT < /dev/tty || PORT=""
    PORT="${PORT:-$DEFAULT_PORT}"
    port_ok "$PORT" && break
  done
  info "port $PORT (entered on the terminal)"
else
  PORT="$DEFAULT_PORT"
  port_ok "$PORT" || die "port $PORT is not usable; run again with --port N"
  info "port $PORT (default; no terminal to ask on)"
fi

# A host that already runs FreeRADIUS for something else must not be overwritten.
step "Checking for an existing FreeRADIUS setup"
if [ ! -e "$BASE/current" ] && [ -f /etc/freeradius/3.0/clients.conf ]; then
  if ! dpkg --verify freeradius-config >/dev/null 2>&1; then
    dpkg --verify freeradius-config 2>&1 | sed 's/^/    changed: /' | head -20 || true
    die "FreeRADIUS is already installed and customized here; this installer needs a clean host"
  fi
  info "FreeRADIUS is installed but unchanged (left by an earlier attempt or installed by hand): OK"
elif [ -e "$BASE/current" ]; then
  info "FreeRADIUS is managed by an existing freeradius-woofweb installation: OK"
else
  info "FreeRADIUS is not installed yet: OK"
fi

export DEBIAN_FRONTEND=noninteractive
PACKAGES=(ca-certificates openssl wget git openssh-client python3 python3-flask python3-werkzeug
  freeradius freeradius-ldap freeradius-utils winbind samba-common-bin libnss-winbind ldap-utils krb5-config)
step "Updating the package lists (apt-get update)"
apt-get update -o APT::Update::Error-Mode=any 2>&1 | sed 's/^/    /' \
  || die "apt cannot reach the package mirrors; check this host's DNS (/etc/resolv.conf) and internet access"
step "Installing packages"
info "${PACKAGES[*]}"
apt-get install -y --no-install-recommends -o Dpkg::Progress-Fancy=0 -o Dpkg::Use-Pty=0 "${PACKAGES[@]}" 2>&1 | sed 's/^/    /' \
  || die "package installation failed (see the apt output above)"
info "installed: python3 $(python3 -c 'import sys; print(sys.version.split()[0])'), flask $(dpkg-query -W -f='${Version}' python3-flask), freeradius $(dpkg-query -W -f='${Version}' freeradius)"

step "Getting the program files"
WORK=$(mktemp -d)
if [ -n "$SOURCE" ]; then
  [ -d "$SOURCE" ] || die "--source $SOURCE is not a directory"
  info "from the local directory $SOURCE"
  tar -C "$SOURCE" --exclude=.git -cf - . | tar -C "$WORK" -xf -
else
  case "$REPO" in OWNER/*) die "REPO is not set in install.sh; use --source for a local copy" ;; esac
  if [ "$VERSION" = main ]; then URL="https://github.com/$REPO/archive/refs/heads/main.tar.gz"
  else URL="https://github.com/$REPO/archive/refs/tags/$VERSION.tar.gz"; fi
  info "downloading $URL"
  wget -nv -O "$WORK/src.tar.gz" "$URL" 2>&1 | sed 's/^/    /' \
    || die "cannot download $URL (check the version name and this host's internet access)"
  info "downloaded $(stat -c %s "$WORK/src.tar.gz") bytes, sha256 $(sha256sum "$WORK/src.tar.gz" | cut -d' ' -f1)"
  tar -C "$WORK" --strip-components=1 -xzf "$WORK/src.tar.gz" || die "the downloaded file is not a valid archive"
  rm -f "$WORK/src.tar.gz"
fi
[ -f "$WORK/VERSION" ] && [ -f "$WORK/app/radius_manager.py" ] || die "the source is not a radius-manager tree"
APP_VERSION=$(tr -d '[:space:]' < "$WORK/VERSION")
[[ "$APP_VERSION" =~ ^[0-9A-Za-z._-]+$ ]] || die "invalid VERSION file"
info "version $APP_VERSION"

step "Creating the service account and directories"
if id radmgr >/dev/null 2>&1; then
  info "account radmgr already exists"
else
  useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin radmgr
  info "created the system account radmgr (runs the web interface without privileges)"
fi
usermod -aG winbindd_priv freerad
info "freerad added to winbindd_priv (needed for AD authentication)"
install -d -o radmgr -g radmgr -m 700 /etc/radius-manager
install -d -o root -g radmgr -m 750 /etc/radius-manager/tls
install -d -o radmgr -g radmgr -m 750 /var/lib/radius-manager /var/log/radius-manager
install -d -o radmgr -g radmgr -m 700 /var/lib/radius-manager/requests /var/lib/radius-manager/backups /var/lib/radius-manager/pending
install -d -o root -g radmgr -m 750 /var/lib/radius-manager/results
install -d -o root -g root -m 700 /var/lib/radius-manager-root /var/lib/radius-manager-root/backups
install -d -o radmgr -g radmgr -m 700 /var/lib/radius-manager/exports
install -d -o freerad -g radmgr -m 2770 /var/log/freeradius/macauth
info "/etc/radius-manager, /var/lib/radius-manager, /var/lib/radius-manager-root, /var/log/radius-manager, /var/log/freeradius/macauth"

step "Installing version $APP_VERSION into $BASE"
RELEASE="$BASE/releases/$APP_VERSION"
PREVIOUS=$(readlink "$BASE/current" 2>/dev/null || true)
mkdir -p "$BASE/releases"
rm -rf "$RELEASE.new"
mkdir "$RELEASE.new"
# install.sh, CHANGELOG.md and project.json are kept so the web updater can roll back to this release.
PARTS=()
for part in app bin freeradius systemd migrations VERSION LICENSE project.json CHANGELOG.md install.sh uninstall.sh; do
  if [ -e "$WORK/$part" ]; then PARTS+=("$part"); fi
done
tar -C "$WORK" -cf - "${PARTS[@]}" | tar -C "$RELEASE.new" --no-same-owner -xf -
chown -R root:root "$RELEASE.new"
find "$RELEASE.new" -type d -exec chmod 755 {} +
find "$RELEASE.new" -type f -exec chmod 644 {} +
chmod 755 "$RELEASE.new"/bin/*
if [ -f "$RELEASE.new/install.sh" ]; then chmod 755 "$RELEASE.new/install.sh"; fi
if [ -f "$RELEASE.new/uninstall.sh" ]; then chmod 755 "$RELEASE.new/uninstall.sh"; fi
rm -rf "$RELEASE"
mv "$RELEASE.new" "$RELEASE"
ln -sfn "$RELEASE" "$BASE/current.new"
mv -T "$BASE/current.new" "$BASE/current"
info "copied: ${PARTS[*]} ($(find "$RELEASE" -type f | wc -l) files)"
info "$BASE/current -> $RELEASE${PREVIOUS:+ (was $PREVIOUS)}"

restore_previous() {
  if [ -n "$PREVIOUS" ] && [ -d "$PREVIOUS" ]; then
    ln -sfn "$PREVIOUS" "$BASE/current"
    "$BASE/current/bin/radius-manager-helper" render || true
    systemctl restart freeradius radius-manager || true
    echo "Restored the previous version: $PREVIOUS" >&2
  fi
}

for name in radius-ssid-policy radius-device-limit radius-group-policy radius-proxy-filter radius-proxy-pap; do
  ln -sfn "$BASE/current/bin/$name" "/usr/local/sbin/$name"
done
ln -sfn "$BASE/current/bin/radius-manager" /usr/local/sbin/radius-manager
info "commands linked in /usr/local/sbin: radius-manager, radius-ssid-policy, radius-device-limit, radius-group-policy, radius-proxy-filter, radius-proxy-pap"

step "Applying the FreeRADIUS configuration (and checking it with freeradius -C)"
if ! "$BASE/current/bin/radius-manager-helper" render 2>&1 | sed 's/^/    /'; then
  restore_previous
  die "FreeRADIUS configuration failed"
fi
info "configuration OK"

step "Writing the web interface settings"
PREFIX_NOW=$(sed -n 's/^FLASK_RADIUS_PREFIX=//p' "$WEB_ENV" 2>/dev/null || true)
URL_PREFIX="${PREFIX_NOW:-$URL_PREFIX}"
( umask 022; printf '# Managed by install.sh. Change the port with: sudo bash install.sh --port N\nFLASK_RADIUS_PORT=%s\nFLASK_RADIUS_PREFIX=%s\n' "$PORT" "$URL_PREFIX" > "$WEB_ENV.new" )
chown root:radmgr "$WEB_ENV.new"; chmod 640 "$WEB_ENV.new"; mv "$WEB_ENV.new" "$WEB_ENV"
info "$WEB_ENV: port $PORT, path $URL_PREFIX/"

if [ ! -f /etc/radius-manager/env ]; then
  TOKEN=$(python3 -I -c 'import secrets; print(secrets.token_urlsafe(24))')
  HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
  KEY=$(python3 -I -c 'import secrets; print(secrets.token_hex(32))')
  ( umask 077; printf 'SECRET_KEY=%s\nSETUP_TOKEN_HASH=%s\nFLASK_DEBUG=0\n' "$KEY" "$HASH" > /etc/radius-manager/env )
  chown radmgr:radmgr /etc/radius-manager/env
  info "/etc/radius-manager/env created with a new session key and a one-time setup token"
else
  TOKEN=""
  info "/etc/radius-manager/env kept (administrator account and session key unchanged)"
fi

if [ ! -f /etc/radius-manager/tls/cert.pem ]; then
  NAME=$(hostname -f 2>/dev/null || hostname)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 3650 \
    -keyout /etc/radius-manager/tls/key.pem -out /etc/radius-manager/tls/cert.pem -subj "/CN=$NAME" \
    -addext "subjectAltName=DNS:$NAME${IP:+,IP:$IP}" 2>/dev/null
  chown root:radmgr /etc/radius-manager/tls/key.pem /etc/radius-manager/tls/cert.pem
  chmod 640 /etc/radius-manager/tls/key.pem /etc/radius-manager/tls/cert.pem
  info "created a self-signed HTTPS certificate for the web interface (CN=$NAME)"
else
  info "web interface HTTPS certificate kept"
fi

step "Starting services"
cp "$BASE/current"/systemd/* /etc/systemd/system/
chmod 644 /etc/systemd/system/radius-manager*
systemctl daemon-reload
systemctl enable --now radius-manager-helper.path radius-manager-macs-restart.path radius-manager-google-dir.timer radius-manager-google-dir.path 2>&1 | sed 's/^/    /'
systemctl enable freeradius radius-manager 2>&1 | sed 's/^/    /'
systemctl restart freeradius
systemctl restart radius-manager

sleep 3
FAILED=""
for unit in freeradius radius-manager radius-manager-helper.path radius-manager-macs-restart.path radius-manager-google-dir.timer; do
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  info "$(printf '%-36s %s' "$unit" "$state")"
  case "$unit" in freeradius|radius-manager) [ "$state" = active ] || FAILED=1 ;; esac
done
if [ -n "$FAILED" ]; then
  journalctl -u radius-manager -u freeradius -n 30 --no-pager 2>&1 | sed 's/^/    /' || true
  restore_previous
  die "services did not start (journal above)"
fi
LISTEN=$(ss -Hltn "sport = :$PORT" 2>/dev/null | awk 'NR==1{print $4}' || true)
info "web interface listening on: ${LISTEN:-not yet}"
info "RADIUS listening on: $(ss -Hlun 'sport = :1812' 2>/dev/null | awk '{print $4}' | paste -sd' ' || true)"

echo
echo "freeradius-woofweb $APP_VERSION is running. (finished in $(( $(date +%s) - STARTED )) seconds)"
if [ -z "$TOKEN" ]; then
  echo "Existing settings were kept. Sign in at https://${IP:-<server-ip>}:$PORT$URL_PREFIX/"
fi
if [ -n "$EXISTING_PORT" ] && [ "$EXISTING_PORT" != "$PORT" ]; then
  echo "The web interface moved from port $EXISTING_PORT to $PORT; update any firewall rule that allowed $EXISTING_PORT."
fi
echo "Install log: $LOG"
if [ -n "$TOKEN" ]; then
  echo "(the one-time setup link was shown on the console only; it is not in this log)"
  finish_log
  # The link is a credential: console only, never written to the log.
  echo
  echo "Open this one-time link to finish the setup (anyone with it can configure the server):"
  echo
  echo "    https://${IP:-<server-ip>}:$PORT$URL_PREFIX/setup?token=$TOKEN"
  echo
  echo "The browser warns about the certificate because it is self-signed; that is expected at this stage."
  echo "Lost the link? Run: sudo radius-manager setup-url"
fi
