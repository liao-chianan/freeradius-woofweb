#!/bin/bash
# freeradius-woofweb installer for a clean Debian 13 host (services and paths are named radius-manager). Running it again upgrades the
# program files and keeps every setting, secret and upload.
#
#   wget -qO- https://raw.githubusercontent.com/liao-chianan/freeradius-woofweb/main/install.sh | sudo bash
#   sudo bash install.sh --source /path/to/checkout    install from a local copy
#   sudo bash install.sh --version v1.2.3              install a specific release
#   sudo bash install.sh --port 8443                    web interface port (default 3333; asked on first install)
# The web interface lives under /woofradius/; any other path returns 404.
set -euo pipefail

# Set this once the repository exists; it is the only place the location is defined.
REPO="${RADMGR_REPO:-liao-chianan/freeradius-woofweb}"
VERSION="main"
SOURCE=""
PORT="${RADMGR_PORT:-}"
BASE=/opt/radius-manager
WEB_ENV=/etc/radius-manager/web.env
DEFAULT_PORT=3333
URL_PREFIX=/woofradius

while [ $# -gt 0 ]; do
  case "$1" in
    --source) SOURCE="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root, for example with sudo"
# Read os-release in a subshell: it defines VERSION, NAME and others that would overwrite this script's variables
# (VERSION="13 (trixie)" replaced the release to download).
OS_INFO=$(. /etc/os-release 2>/dev/null; printf '%s|%s|%s' "${ID:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-unknown}")
IFS='|' read -r OS_ID OS_VERSION_ID OS_PRETTY <<< "$OS_INFO"
[ "$OS_ID" = debian ] && [ "$OS_VERSION_ID" = 13 ] || die "only Debian 13 is supported (found $OS_PRETTY)"
command -v systemctl >/dev/null || die "systemd is required"

# ---- web interface port ----
port_ok() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] || { echo "the port must be a number" >&2; return 1; }
  [ "$1" -ge 1024 ] && [ "$1" -le 65535 ] || { echo "the port must be 1024-65535 (the service runs without privileges)" >&2; return 1; }
  case "$1" in 1812|1813|18120) echo "port $1 is used by FreeRADIUS" >&2; return 1 ;; esac
  # A port held by radius-manager itself (an upgrade, or moving back) is fine.
  local main; main=$(systemctl show -p MainPID --value radius-manager 2>/dev/null || echo 0)
  if ss -Hltnp "sport = :$1" 2>/dev/null | grep -v "pid=${main:-0}," | grep -q .; then
    echo "port $1 is already in use on this host" >&2; return 1
  fi
}
EXISTING_PORT=$(sed -n 's/^FLASK_RADIUS_PORT=//p' "$WEB_ENV" 2>/dev/null || true)
# Installed before the port became selectable: it has always been 3333.
[ -z "$EXISTING_PORT" ] && [ -f /etc/radius-manager/env ] && EXISTING_PORT=$DEFAULT_PORT
if [ -n "$PORT" ]; then
  port_ok "$PORT" || die "invalid --port"
elif [ -n "$EXISTING_PORT" ]; then
  PORT="$EXISTING_PORT"                     # upgrade: keep the port chosen before
elif [ -r /dev/tty ] && [ -w /dev/tty ] && { : < /dev/tty; } 2>/dev/null; then
  # stdin is the downloaded script when run as "wget ... | sudo bash", so ask on the terminal
  while :; do
    printf 'Web interface port [%s]: ' "$DEFAULT_PORT" > /dev/tty
    IFS= read -r PORT < /dev/tty || PORT=""
    PORT="${PORT:-$DEFAULT_PORT}"
    port_ok "$PORT" && break
  done
else
  PORT="$DEFAULT_PORT"
  port_ok "$PORT" || die "port $PORT is not usable; run again with --port N"
fi

# A host that already runs FreeRADIUS for something else must not be overwritten.
if [ ! -e "$BASE/current" ] && [ -f /etc/freeradius/3.0/clients.conf ] && ! dpkg --verify freeradius-config >/dev/null 2>&1; then
  die "FreeRADIUS is already installed and customized here; this installer needs a clean host"
fi

export DEBIAN_FRONTEND=noninteractive
echo "==> Installing packages"
apt-get update -qq -o APT::Update::Error-Mode=any || die "apt cannot reach the package mirrors; check this host's DNS (/etc/resolv.conf) and internet access"
apt-get install -y -qq --no-install-recommends ca-certificates openssl wget git openssh-client python3 python3-flask python3-werkzeug \
  freeradius freeradius-ldap freeradius-utils winbind samba-common-bin libnss-winbind ldap-utils krb5-config >/dev/null

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
if [ -n "$SOURCE" ]; then
  tar -C "$SOURCE" --exclude=.git -cf - . | tar -C "$WORK" -xf -
else
  case "$REPO" in OWNER/*) die "REPO is not set in install.sh; use --source for a local copy" ;; esac
  if [ "$VERSION" = main ]; then URL="https://github.com/$REPO/archive/refs/heads/main.tar.gz"
  else URL="https://github.com/$REPO/archive/refs/tags/$VERSION.tar.gz"; fi
  echo "==> Downloading $URL"
  wget -qO "$WORK/src.tar.gz" "$URL" || die "cannot download $URL (check the version name and this host's internet access)"
  tar -C "$WORK" --strip-components=1 -xzf "$WORK/src.tar.gz" || die "the downloaded file is not a valid archive"
  rm -f "$WORK/src.tar.gz"
fi
[ -f "$WORK/VERSION" ] && [ -f "$WORK/app/radius_manager.py" ] || die "the source is not a radius-manager tree"
APP_VERSION=$(tr -d '[:space:]' < "$WORK/VERSION")
[[ "$APP_VERSION" =~ ^[0-9A-Za-z._-]+$ ]] || die "invalid VERSION file"

echo "==> Creating the service account and directories"
id radmgr >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin radmgr
usermod -aG winbindd_priv freerad
install -d -o radmgr -g radmgr -m 700 /etc/radius-manager
install -d -o root -g radmgr -m 750 /etc/radius-manager/tls
install -d -o radmgr -g radmgr -m 750 /var/lib/radius-manager /var/log/radius-manager
install -d -o radmgr -g radmgr -m 700 /var/lib/radius-manager/requests /var/lib/radius-manager/backups /var/lib/radius-manager/pending
install -d -o root -g radmgr -m 750 /var/lib/radius-manager/results
install -d -o root -g root -m 700 /var/lib/radius-manager-root /var/lib/radius-manager-root/backups
install -d -o radmgr -g radmgr -m 700 /var/lib/radius-manager/exports
install -d -o freerad -g radmgr -m 2770 /var/log/freeradius/macauth

echo "==> Installing version $APP_VERSION"
RELEASE="$BASE/releases/$APP_VERSION"
PREVIOUS=$(readlink "$BASE/current" 2>/dev/null || true)
mkdir -p "$BASE/releases"
rm -rf "$RELEASE.new"
mkdir "$RELEASE.new"
# install.sh, CHANGELOG.md and project.json are kept so the web updater can roll back to this release.
PARTS=()
for part in app bin freeradius systemd migrations VERSION LICENSE project.json CHANGELOG.md install.sh uninstall.sh; do
  [ -e "$WORK/$part" ] && PARTS+=("$part")
done
tar -C "$WORK" -cf - "${PARTS[@]}" | tar -C "$RELEASE.new" --no-same-owner -xf -
chown -R root:root "$RELEASE.new"
find "$RELEASE.new" -type d -exec chmod 755 {} +
find "$RELEASE.new" -type f -exec chmod 644 {} +
chmod 755 "$RELEASE.new"/bin/*
[ -f "$RELEASE.new/install.sh" ] && chmod 755 "$RELEASE.new/install.sh" "$RELEASE.new/uninstall.sh" 2>/dev/null || true
rm -rf "$RELEASE"
mv "$RELEASE.new" "$RELEASE"
ln -sfn "$RELEASE" "$BASE/current.new"
mv -T "$BASE/current.new" "$BASE/current"

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

echo "==> Applying the FreeRADIUS configuration"
"$BASE/current/bin/radius-manager-helper" render || { restore_previous; die "FreeRADIUS configuration failed"; }

PREFIX_NOW=$(sed -n 's/^FLASK_RADIUS_PREFIX=//p' "$WEB_ENV" 2>/dev/null || true)
URL_PREFIX="${PREFIX_NOW:-$URL_PREFIX}"
( umask 022; printf '# Managed by install.sh. Change the port with: sudo bash install.sh --port N\nFLASK_RADIUS_PORT=%s\nFLASK_RADIUS_PREFIX=%s\n' "$PORT" "$URL_PREFIX" > "$WEB_ENV.new" )
chown root:radmgr "$WEB_ENV.new"; chmod 640 "$WEB_ENV.new"; mv "$WEB_ENV.new" "$WEB_ENV"

if [ ! -f /etc/radius-manager/env ]; then
  TOKEN=$(python3 -I -c 'import secrets; print(secrets.token_urlsafe(24))')
  HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
  KEY=$(python3 -I -c 'import secrets; print(secrets.token_hex(32))')
  ( umask 077; printf 'SECRET_KEY=%s\nSETUP_TOKEN_HASH=%s\nFLASK_DEBUG=0\n' "$KEY" "$HASH" > /etc/radius-manager/env )
  chown radmgr:radmgr /etc/radius-manager/env
else
  TOKEN=""
fi

IP=$(ip -4 route get 192.0.2.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
if [ ! -f /etc/radius-manager/tls/cert.pem ]; then
  NAME=$(hostname -f 2>/dev/null || hostname)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 3650 \
    -keyout /etc/radius-manager/tls/key.pem -out /etc/radius-manager/tls/cert.pem -subj "/CN=$NAME" \
    -addext "subjectAltName=DNS:$NAME${IP:+,IP:$IP}" 2>/dev/null
  chown root:radmgr /etc/radius-manager/tls/key.pem /etc/radius-manager/tls/cert.pem
  chmod 640 /etc/radius-manager/tls/key.pem /etc/radius-manager/tls/cert.pem
fi

echo "==> Starting services"
cp "$BASE/current"/systemd/* /etc/systemd/system/
chmod 644 /etc/systemd/system/radius-manager*
systemctl daemon-reload
systemctl enable --now radius-manager-helper.path radius-manager-macs-restart.path radius-manager-google-dir.timer radius-manager-google-dir.path >/dev/null
systemctl enable freeradius radius-manager >/dev/null
systemctl restart freeradius
systemctl restart radius-manager

sleep 3
if ! systemctl is-active --quiet freeradius || ! systemctl is-active --quiet radius-manager; then
  journalctl -u radius-manager -u freeradius -n 15 --no-pager >&2 || true
  restore_previous
  die "services did not start"
fi

echo
echo "freeradius-woofweb $APP_VERSION is running."
if [ -n "$TOKEN" ]; then
  echo
  echo "Open this one-time link to finish the setup (anyone with it can configure the server):"
  echo
  echo "    https://${IP:-<server-ip>}:$PORT$URL_PREFIX/setup?token=$TOKEN"
  echo
  echo "The browser warns about the certificate because it is self-signed; that is expected at this stage."
  echo "Lost the link? Run: sudo radius-manager setup-url"
else
  echo "Existing settings were kept. Sign in at https://${IP:-<server-ip>}:$PORT$URL_PREFIX/"
fi
if [ -n "$EXISTING_PORT" ] && [ "$EXISTING_PORT" != "$PORT" ]; then
  echo "The web interface moved from port $EXISTING_PORT to $PORT; update any firewall rule that allowed $EXISTING_PORT."
fi
