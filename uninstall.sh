#!/bin/bash
# Removes radius-manager and everything it configured: settings, device list, logs, certificates.
# It also purges FreeRADIUS and Samba, which were installed for it. There is no undo.
#   sudo bash uninstall.sh --yes
set -u
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ "${1:-}" = "--yes" ] || { echo "This deletes all settings and data. To continue: sudo bash uninstall.sh --yes" >&2; exit 2; }
systemctl disable --now radius-manager radius-manager-helper.path radius-manager-macs-restart.path \
  radius-manager-ad-status.timer radius-manager-ad-status.path radius-manager-google-dir.timer radius-manager-google-dir.path 2>/dev/null
systemctl stop freeradius winbind 2>/dev/null
rm -f /etc/systemd/system/radius-manager* /usr/local/sbin/radius-manager /usr/local/sbin/radius-ssid-policy /usr/local/sbin/radius-device-limit /usr/local/sbin/radius-group-policy /usr/local/sbin/radius-proxy-filter /usr/local/sbin/radius-proxy-pap
systemctl daemon-reload
export DEBIAN_FRONTEND=noninteractive
apt-get purge -y -qq 'freeradius*' winbind samba-common-bin samba-common libnss-winbind >/dev/null
apt-get autoremove -y -qq --purge >/dev/null
rm -rf /opt/radius-manager /etc/radius-manager /var/lib/radius-manager /var/lib/radius-manager-root /var/log/radius-manager \
  /etc/freeradius /var/log/freeradius /etc/samba /etc/krb5.conf /var/lib/samba /var/cache/samba
userdel radmgr 2>/dev/null
echo "freeradius-woofweb (radius-manager) was removed."
