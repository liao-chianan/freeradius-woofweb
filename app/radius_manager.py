from flask import abort, Flask, render_template, request, Response, redirect as flask_redirect, session, flash, jsonify, url_for
import os
import csv
import re
import logging
import io
import json
import hashlib
import hmac
import tempfile
import shutil
import secrets
import fcntl
import time
import sqlite3
import threading
import ipaddress
import socket
import ssl
from contextlib import contextmanager
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlsplit
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import ThreadedWSGIServer

# 名單改動後由 systemd 的 freeradius-macs-restart.path 偵測並重啟 FreeRADIUS，程式本身不需 root
DATA_FILE = os.environ.get('RADIUS_DATA_FILE', '/etc/freeradius/3.0/authorized_macs')
TLS_CERT = os.environ.get('FLASK_RADIUS_TLS_CERT', '/etc/radius-manager/tls/cert.pem')
TLS_KEY = os.environ.get('FLASK_RADIUS_TLS_KEY', '/etc/radius-manager/tls/key.pem')
APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.environ.get('FLASK_RADIUS_ENV', '/etc/radius-manager/env')
STATE_DIR = os.environ.get('FLASK_RADIUS_STATE', '/var/lib/radius-manager')
LOG_DIR = os.environ.get('FLASK_RADIUS_LOG_DIR', '/var/log/radius-manager')
METADATA_FILE = os.path.join(STATE_DIR, 'metadata.json')
BACKUP_DIR = os.path.join(STATE_DIR, 'backups')
PENDING_DIR = os.path.join(STATE_DIR, 'pending')
LOCK_FILE = os.path.join(STATE_DIR, 'lock')
BACKUP_KEEP = 30
PENDING_MAX_AGE = 3600
AUTH_LOG_DIR = os.environ.get('FLASK_RADIUS_AUTH_DIR', '/var/log/freeradius/macauth')
AUTH_DB = os.path.join(STATE_DIR, 'logins.db')
SETTINGS_FILE = os.path.join(STATE_DIR, 'settings.json')
AUTH_LOG_RE = re.compile(r'(auth|ad|fail|google|proxy)-(\d{8})\.log')
GOOGLE_LIMIT_PREFIX = 'google:'
MAX_ALLOWED_CIDRS = 100
DEFAULT_FAIL_RETENTION_DAYS = 14
MAX_FAIL_RETENTION_DAYS = 365
FAIL_PAGE_SIZE = 100
FAIL_STATS_LIMIT = 50
FAIL_GROUPS = {'mac': '裝置 MAC', 'account': 'AD 帳號', 'google': 'Google 帳號', 'proxy': '外部帳號', 'ssid': 'SSID', 'ap': 'AP', 'reason': '失敗原因'}
# 三種帳號都存在 auth_failures.account，用 kind 區分
FAIL_ACCOUNT_KINDS = {'account': "kind NOT IN ('google', 'proxy')", 'google': "kind = 'google'", 'proxy': "kind = 'proxy'"}
# 由上而下比對 FreeRADIUS 的訊息，第一個吻合的就是顯示的原因
FAIL_REASONS = (('Proxy server rejected: E=691', '外部 RADIUS 拒絕：帳號或密碼錯誤'), ('Proxy server rejected: E=647', '外部 RADIUS 拒絕：帳號已停用'),
                ('Proxy server rejected: E=648', '外部 RADIUS 拒絕：密碼已過期'), ('Proxy server rejected: E=649', '外部 RADIUS 拒絕：帳號沒有連線權限'),
                ('Proxy server rejected: E=646', '外部 RADIUS 拒絕：不在允許的時段'), ('Proxy server rejected: E=709', '外部 RADIUS 拒絕：密碼必須變更'),
                ('Proxy server rejected (PAP)', '外部 RADIUS 拒絕：帳號或密碼錯誤'), ('Proxy server rejected', '外部 RADIUS 拒絕'),
                ('Proxy server no response or error', '外部 RADIUS 沒有回應或設定錯誤'), ('lack of any response from home server', '外部 RADIUS 沒有回應'),
                ('Proxy account blacklisted', '符合 Proxy 黑名單'), ('Proxy account not in whitelist', '不在 Proxy 白名單'),
                ('Proxy not configured', 'Proxy 代理未設定'), ('Proxy SSID requires', '裝置的驗證方式與 Proxy 設定不符'),
                ('0xc000006d', '帳號或密碼錯誤'), ('0xc000006a', '帳號或密碼錯誤'), ('0xc0000064', '帳號不存在'),
                ('0xc0000072', 'AD 帳號已停用'), ('0xc0000234', 'AD 帳號已鎖定'), ('0xc0000193', 'AD 帳號已過期'),
                ('0xc0000071', 'AD 密碼已過期'), ('0xc0000224', 'AD 密碼必須變更'),
                ('Google SSID requires', '裝置未使用 PEAP-GTC 或 EAP-TTLS/PAP'), ('ldap_google: User object not found', 'Google 帳號不存在'),
                ('ldap_google: Empty password', '密碼空白'), ('ldap_google: Bind', 'Google 帳號或密碼錯誤'), ('ldap_google: ', 'Google LDAP 查詢失敗'),
                ('Daily device limit', '超過裝置數上限'), ('Account blacklisted', '帳號在黑名單中'), ('Wi-Fi group not allowed', '所屬群組或機構未開放 Wi-Fi'), ('SSID rule rejected', 'SSID 規則拒絕'),
                ('unknown CA', '裝置不信任伺服器憑證'), ('previously rejected', '先前已被拒絕'),
                ('No Auth-Type found', '此 SSID 不接受這種驗證方式'))
DEVICE_LIMIT_FILE = os.path.join(AUTH_LOG_DIR, 'device-limit.json')
DEVICE_LIMIT_DB = os.path.join(AUTH_LOG_DIR, 'device-limit.db')
SSID_RULES_FILE = os.path.join(AUTH_LOG_DIR, 'ssid-rules.json')
GROUP_POLICY_FILE = os.path.join(AUTH_LOG_DIR, 'group-policy.json')
BLACKLIST_FILE = os.path.join(AUTH_LOG_DIR, 'blacklist.json')
MAX_BLACKLIST = 2000
GOOGLE_EMAIL_RE = re.compile(r'[^\s@|]{1,64}@[^\s@|]{1,190}')
GOOGLE_DIR_FILE = os.path.join(STATE_DIR, 'google_directory.json')
PROXY_FILTER_FILE = os.path.join(AUTH_LOG_DIR, 'proxy-filter.json')
PROXY_INFO_FILE = os.path.join(STATE_DIR, 'proxy.json')
MAX_PROXY_KEYWORDS = 200
PROXY_RECENT_FAILURES = 50
# 外層、內層的可用組合（PEAP 的內層一定是 EAP，沒有 PAP）。與 radius-proxy-filter 相同。
PROXY_METHODS = (('PEAP', 'MSCHAPv2'), ('PEAP', 'GTC'), ('TTLS', 'PAP'), ('TTLS', 'MSCHAPv2'), ('TTLS', 'GTC'))
PROXY_METHOD_NOTES = {
    ('PEAP', 'MSCHAPv2'): '轉送給外部時用 MS-CHAPv2。外部要能驗 MS-CHAPv2（需要 NT 雜湊；帳號放在 LDAP、Google 的通常不行）。Windows、Android、iOS 預設就是這種。',
    ('PEAP', 'GTC'): '轉送給外部時用 PAP（明文密碼，在本機與外部之間以共用金鑰加密）。Windows 內建不支援 PEAP-GTC；iOS 要用描述檔；Android 第二階段選 GTC。',
    ('TTLS', 'PAP'): '轉送給外部時用 PAP。幾乎所有 RADIUS 都接受。Windows 10/11、Android、iOS 都支援（Android 第二階段選 PAP）。',
    ('TTLS', 'MSCHAPv2'): '轉送給外部時用 MS-CHAPv2。裝置的第二階段要選非 EAP 的 MSCHAPv2（Windows 選「Microsoft: MS-CHAP v2」，不是 EAP-MSCHAPv2）。',
    ('TTLS', 'GTC'): '轉送給外部時用 PAP。裝置的第二階段要選 EAP-GTC，支援的裝置較少。',
}
GOOGLE_REFRESH_FILE = os.path.join(STATE_DIR, 'google_refresh')
GOOGLE_DIR_STALE = 7200
GROUP_SOURCES = {'ad': {'title': 'AD 群組', 'item': '群組', 'page': '/ad', 'member': '帳號'},
                 'google': {'title': 'Google 機構', 'item': '機構', 'page': '/google', 'member': '使用者'}}
GOOGLE_ROOT_LABEL = '（最上層）'
SSID_AUTH_LABELS = {'mac': '放行裝置名單', 'ad': 'AD 帳號', 'google': 'Google 帳號', 'proxy': 'Proxy 代理', 'reject': '拒絕'}
DEFAULT_SSID_RULES = {'rules': [{'keyword': 'Device', 'auth': 'mac', 'vlan': ''}, {'keyword': 'Staff', 'auth': 'ad', 'vlan': ''}],
                      'default': {'auth': 'ad', 'vlan': ''}}
MAX_SSID_RULES = 50
SSID_SEEN_DAYS = 30
DEFAULT_DEVICE_LIMIT = 3
MAX_DEVICE_LIMIT = 50
# 週期從 00:00 起算，必須能整除 24，才不會跨日
DEVICE_WINDOW_CHOICES = (1, 2, 3, 4, 6, 8, 12, 24)
DEFAULT_DEVICE_WINDOW = 24
ACCOUNT_RE = re.compile(r'[\w.$-][\w.$ -]{0,63}')
DEFAULT_LOGIN_RETENTION = 50
MAX_LOGIN_RETENTION = 10000
INGEST_INTERVAL = 30
AD_STATUS_FILE = os.path.join(STATE_DIR, 'ad_status.json')
AD_STATUS_STALE = 1800
AD_REFRESH_FILE = os.path.join(STATE_DIR, 'ad_refresh')
AD_REFRESH_MIN_AGE = 30
AD_REFRESH_WAIT = 20
AP_FILE = os.path.join(STATE_DIR, 'ap_list.json')
AP_BACKUP_DIR = os.path.join(STATE_DIR, 'ap-backups')
AP_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
AP_FIELD_LABELS = {'name': '裝置名稱', 'ip': 'IP', 'mac': 'MAC'}

logging.basicConfig(filename=os.path.join(LOG_DIR, 'radius-manager.log'), level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s',datefmt='%Y-%m-%d %H:%M:%S')

# 異動紀錄獨立一個檔案，一行一筆 JSON
change_log = logging.getLogger('changes')
change_log.propagate = False
_change_handler = logging.FileHandler(os.path.join(LOG_DIR, 'changes.log'), encoding='utf-8')
_change_handler.setFormatter(logging.Formatter('%(message)s'))
change_log.addHandler(_change_handler)
change_log.setLevel(logging.INFO)

DEFAULT_VLAN = '1'


def default_attrs():
    return {'tunnel_type': '13', 'tunnel_medium': '6', 'tunnel_group': str(load_settings().get('default_vlan', DEFAULT_VLAN))}


FIELD_LABELS = {
    'id': '裝置名稱',
    'mac': 'MAC',
    'tunnel_type': 'Tunnel-Type',
    'tunnel_medium': 'Medium-Type',
    'tunnel_group': 'VLAN (Group-ID)'
}

ID_RE = re.compile(r'[A-Za-z0-9_.-]{1,64}')
MAC_RE = re.compile(r'([0-9A-F]{2}-){5}[0-9A-F]{2}')
USERNAME_RE = re.compile(r'[A-Za-z0-9_.-]{3,32}')
MIN_PASSWORD_LENGTH = 12
ATTR_RES = {
    'tunnel_type': re.compile(r'Tunnel-Type\s*=\s*(\S+?),?'),
    'tunnel_medium': re.compile(r'Tunnel-Medium-Type\s*=\s*(\S+?),?'),
    'tunnel_group': re.compile(r'Tunnel-Private-Group-ID\s*=\s*(\S+?),?')
}


def app_version():
    try:
        with open(os.path.join(APP_ROOT, 'VERSION'), encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return ''


def load_env():
    env = {}
    with open(ENV_FILE, 'r') as f:
        for line in f:
            if '=' in line:
                k, v = line.strip().split('=', 1)
                env[k] = v
    return env


def save_credentials(username, password_hash):
    env = load_env()
    env.pop('SETUP_TOKEN_HASH', None)
    env['ADMIN_USERNAME'] = username
    env['ADMIN_PASSWORD_HASH'] = password_hash
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(ENV_FILE))
    try:
        with os.fdopen(fd, 'w') as f:
            for k, v in env.items():
                f.write(f"{k}={v}\n")
        os.replace(tmp, ENV_FILE)
    except Exception:
        os.unlink(tmp)
        raise


def credential_tag(env):
    # 帳密變更後，舊的 session 一律失效
    if not env.get('ADMIN_PASSWORD_HASH'):
        return ''
    return hashlib.sha256(f"{env['ADMIN_USERNAME']}:{env['ADMIN_PASSWORD_HASH']}".encode()).hexdigest()[:16]


app = Flask(__name__)
app.secret_key = load_env()['SECRET_KEY']
# 管理介面只在這個路徑底下，其他路徑一律 404，避免外部掃描直接看到登入頁。可在 /etc/radius-manager/web.env 改。
URL_PREFIX = os.environ.get('FLASK_RADIUS_PREFIX', '/woofradius').rstrip('/')
if not re.fullmatch(r'(/[A-Za-z0-9_-]{1,64}){1,4}', URL_PREFIX):
    raise SystemExit(f'FLASK_RADIUS_PREFIX must look like /woofradius, got {URL_PREFIX!r}')


class PrefixMiddleware:
    """把 /woofradius/... 交給 Flask（SCRIPT_NAME 設為前綴，url_for 與靜態檔會自動帶上），其他路徑回最簡單的 404。"""

    def __init__(self, wsgi_app, prefix):
        self.wsgi_app, self.prefix = wsgi_app, prefix

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '')
        if path == self.prefix:
            start_response('302 Found', [('Location', self.prefix + '/'), ('Content-Length', '0')])
            return [b'']
        if path.startswith(self.prefix + '/'):
            environ['SCRIPT_NAME'] = environ.get('SCRIPT_NAME', '') + self.prefix
            environ['PATH_INFO'] = path[len(self.prefix):]
            return self.wsgi_app(environ, start_response)
        start_response('404 Not Found', [('Content-Type', 'text/plain'), ('Content-Length', '10')])
        return [b'Not Found\n']


app.wsgi_app = PrefixMiddleware(app.wsgi_app, URL_PREFIX)
app.config['SESSION_COOKIE_PATH'] = URL_PREFIX + '/'


def redirect(location, code=302):
    """程式裡寫的都是 /ad 這種站內路徑，送出前加上前綴。"""
    if location.startswith('/') and not location.startswith('//'):
        location = request.script_root + location
    return flask_redirect(location, code)


app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.path.exists(TLS_CERT)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024


@contextmanager
def data_lock():
    with open(LOCK_FILE, 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def load_metadata():
    if not os.path.exists(METADATA_FILE):
        return {}
    with open(METADATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_metadata(metadata):
    fd, tmp = tempfile.mkstemp(dir=STATE_DIR)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=0, sort_keys=True)
        os.replace(tmp, METADATA_FILE)
    except Exception:
        os.unlink(tmp)
        raise


def read_list():
    """回傳 (entries, version, problems)。problems 不為空代表檔案結構異常，不可寫入。"""
    if not os.path.exists(DATA_FILE):
        return [], '', []
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        raw = f.read()
    version = hashlib.sha256(raw.encode()).hexdigest()
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    metadata = load_metadata()
    entries = []
    problems = []
    for i in range(0, len(lines), 5):
        group = lines[i:i + 5]
        attrs = {}
        ok = len(group) == 5 and group[0].startswith('#') and MAC_RE.fullmatch(group[1].upper())
        if ok:
            for offset, (field, pattern) in enumerate(ATTR_RES.items()):
                m = pattern.fullmatch(group[2 + offset])
                if not m:
                    ok = False
                    break
                attrs[field] = m.group(1)
        if not ok:
            problems.append(f"第 {i // 5 + 1} 筆（非空白第 {i + 1} 行起）格式異常")
            continue
        mac = group[1].upper()
        entries.append({'id': group[0][1:], 'mac': mac, 'modified': metadata.get(mac, ''), **attrs})
    return entries, version, problems


def write_list(entries):
    text = ''
    for e in entries:
        text += f"#{e['id']}\n"
        text += f"{e['mac']}\n"
        text += f"        Tunnel-Type = {e['tunnel_type']},\n"
        text += f"        Tunnel-Medium-Type = {e['tunnel_medium']},\n"
        text += f"        Tunnel-Private-Group-ID = {e['tunnel_group']}\n\n"
    # 名單是 bind mount 進來的單一檔案，無法用 rename 替換，只能就地寫入
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())


def make_backup(op):
    name = f"{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}-{op}"
    path = os.path.join(BACKUP_DIR, name)
    os.makedirs(path, mode=0o700)
    shutil.copy2(DATA_FILE, os.path.join(path, 'authorized_macs'))
    if os.path.exists(METADATA_FILE):
        shutil.copy2(METADATA_FILE, os.path.join(path, 'metadata.json'))
    for old in sorted(os.listdir(BACKUP_DIR))[:-BACKUP_KEEP]:
        shutil.rmtree(os.path.join(BACKUP_DIR, old))
    return name


def actor():
    return {'user': session.get('user'), 'ip': request.remote_addr}


def log_change(record):
    change_log.info(json.dumps({'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), **actor(), **record}, ensure_ascii=False))


def now_text():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def public_entry(e):
    return {k: e.get(k, '') for k in ('id', 'mac', 'tunnel_type', 'tunnel_medium', 'tunnel_group', 'modified')}


def entry_diff(before, after):
    return {f: [before[f], after[f]] for f in FIELD_LABELS if before[f] != after[f]}


def commit(op, new_entries, touched_macs, removed_macs, log_records, stamp, summary=None):
    """先備份再寫入。呼叫端需持有 data_lock。寫入失敗時由備份還原。"""
    backup = make_backup(op)
    metadata = load_metadata()
    for mac in removed_macs:
        metadata.pop(mac, None)
    for mac in touched_macs:
        metadata[mac] = stamp
    try:
        write_list(new_entries)
    except Exception:
        shutil.copyfile(os.path.join(BACKUP_DIR, backup, 'authorized_macs'), DATA_FILE)
        raise
    save_metadata(metadata)
    if summary is not None:
        log_change({'op': op + '_SUMMARY', 'backup': backup, **summary})
    for record in log_records:
        log_change({'op': op, 'backup': backup, **record})
    return backup


def normalize_mac(value):
    return value.strip().upper().replace(':', '-')


def load_settings():
    settings = {'login_retention': DEFAULT_LOGIN_RETENTION, 'fail_retention_days': DEFAULT_FAIL_RETENTION_DAYS}
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            settings.update(json.load(f))
    return settings


def save_settings(settings):
    fd, tmp = tempfile.mkstemp(dir=STATE_DIR)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=0, sort_keys=True)
        os.replace(tmp, SETTINGS_FILE)
    except Exception:
        os.unlink(tmp)
        raise


def load_device_limit():
    try:
        with open(DEVICE_LIMIT_FILE, encoding='utf-8') as f:
            config = json.load(f)
        window = int(config.get('window_hours', DEFAULT_DEVICE_WINDOW))
        return {'limit': int(config['limit']), 'exempt': list(config.get('exempt', [])),
                'window_hours': window if window in DEVICE_WINDOW_CHOICES else DEFAULT_DEVICE_WINDOW,
                'reset_all': int(config.get('reset_all', 0)),
                'resets': {str(k): int(v) for k, v in dict(config.get('resets', {})).items()}}
    except (OSError, ValueError, KeyError, TypeError):
        return {'limit': DEFAULT_DEVICE_LIMIT, 'exempt': [], 'window_hours': DEFAULT_DEVICE_WINDOW, 'reset_all': 0, 'resets': {}}


def save_radius_json(path, config):
    # FreeRADIUS（freerad）要能讀，內容沒有機密
    fd, tmp = tempfile.mkstemp(dir=AUTH_LOG_DIR, prefix='.radius-json-')
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=0, sort_keys=True, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        os.unlink(tmp)
        raise


def save_device_limit(config):
    save_radius_json(DEVICE_LIMIT_FILE, config)


def load_ssid_rules():
    try:
        with open(SSID_RULES_FILE, encoding='utf-8') as f:
            config = json.load(f)
        return {'rules': [{k: str(r[k]) for k in ('keyword', 'auth', 'vlan')} for r in config['rules']],
                'default': {k: str(config['default'][k]) for k in ('auth', 'vlan')}}
    except (OSError, ValueError, KeyError, TypeError):
        return json.loads(json.dumps(DEFAULT_SSID_RULES))


def validate_ssid_rules(rules, default):
    """回傳錯誤訊息，沒問題回傳 None。"""
    if len(rules) > MAX_SSID_RULES:
        return f'規則最多 {MAX_SSID_RULES} 筆'
    seen = set()
    for rule in [*rules, default]:
        if rule.get('auth') not in SSID_AUTH_LABELS:
            return '驗證方式不在可選擇的範圍內'
        vlan = rule.get('vlan', '')
        if vlan and not (re.fullmatch(r'[0-9]{1,4}', vlan) and 1 <= int(vlan) <= 4094):
            return f'VLAN 必須是 1 到 4094 的數字，或留白：{vlan}'
        if vlan and rule['auth'] == 'reject':
            return '拒絕的規則不可設定 VLAN'
    for rule in rules:
        keyword = rule.get('keyword', '')
        if not keyword or len(keyword.encode('utf-8')) > 32 or not keyword.isprintable():
            return f'SSID 關鍵字必須是 1 到 32 bytes 的可見文字：{keyword}'
        if keyword.lower() in seen:
            return f'SSID 關鍵字重複：{keyword}'
        seen.add(keyword.lower())
    return None


def match_ssid(config, ssid):
    """與 radius-ssid-policy 相同的判斷：第一個吻合的關鍵字生效，不分大小寫。"""
    for rule in config['rules']:
        if rule['keyword'].lower() in ssid.lower():
            return {**rule, 'source': f"關鍵字 {rule['keyword']}"}
    return {**config['default'], 'source': '沒有吻合的關鍵字'}


def ssid_result_text(result):
    if result['auth'] == 'reject':
        return '拒絕'
    if result['vlan']:
        return f"{SSID_AUTH_LABELS[result['auth']]}，VLAN {result['vlan']}"
    return f"{SSID_AUTH_LABELS[result['auth']]}，" + ('VLAN 依名單' if result['auth'] == 'mac' else '不發 VLAN')


def seen_ssids():
    """最近實際登入過的 SSID 與次數，讓管理者在套用前看到規則的影響。"""
    ingest_logins()
    seen = {}
    since = int(time.time()) - SSID_SEEN_DAYS * 86400
    conn = open_db()
    try:
        for table, kind in (('logins', 'mac'), ('ad_logins', 'ad'), ('google_logins', 'google'), ('proxy_logins', 'proxy')):
            for called, count in conn.execute(f'SELECT called, COUNT(*) FROM {table} WHERE ts >= ? AND called != ? GROUP BY called', (since, '')):
                ssid = split_called(called)[1]
                if ssid:
                    row = seen.setdefault(ssid, {'ssid': ssid, 'mac': 0, 'ad': 0, 'google': 0, 'proxy': 0})
                    row[kind] += count
    finally:
        conn.close()
    return sorted(seen.values(), key=lambda r: r['ssid'].lower())


def ssid_impact(before, after):
    rows = []
    for row in seen_ssids():
        old, new = match_ssid(before, row['ssid']), match_ssid(after, row['ssid'])
        warning = ''
        if new['auth'] == 'reject':
            warning = '這個 SSID 的登入會全部被拒絕'
        elif row['mac'] and new['auth'] != 'mac':
            warning = '目前有名單裝置從這個 SSID 登入，改用其他驗證方式後這些裝置會登入失敗'
        elif row['ad'] and new['auth'] != 'ad':
            warning = '目前有 AD 帳號從這個 SSID 登入，改用其他驗證方式後這些帳號會登入失敗'
        elif row['google'] and new['auth'] != 'google':
            warning = '目前有 Google 帳號從這個 SSID 登入，改用其他驗證方式後這些帳號會登入失敗'
        elif row['proxy'] and new['auth'] != 'proxy':
            warning = '目前有外部帳號從這個 SSID 經 Proxy 代理登入，改用其他驗證方式後這些帳號會登入失敗'
        elif new['auth'] == 'proxy' and not load_proxy_info():
            warning = '尚未設定外部 RADIUS，這個 SSID 的登入會全部被拒絕'
        rows.append({**row, 'before': ssid_result_text(old), 'after': ssid_result_text(new), 'source': new['source'],
                     'changed': ssid_result_text(old) != ssid_result_text(new), 'warning': warning})
    return rows


def device_window(window_hours, now=None):
    """回傳目前週期的開始與下一次重置時間。"""
    current = datetime.fromtimestamp(time.time() if now is None else now)
    midnight = current.replace(hour=0, minute=0, second=0, microsecond=0)
    start = midnight + timedelta(hours=current.hour // window_hours * window_hours)
    return start, start + timedelta(hours=window_hours)


def device_limit_current(limit):
    """回傳目前週期每個帳號的裝置數與被拒絕的裝置。資料庫由 FreeRADIUS 寫入，這裡只讀。"""
    counts, denied = {}, {}
    day = time.strftime('%Y-%m-%d')
    period_start = int(device_window(limit['window_hours'])[0].timestamp())

    def since(account):
        return max(period_start, limit['reset_all'], limit['resets'].get(account, 0))
    try:
        conn = sqlite3.connect(f'file:{DEVICE_LIMIT_DB}?mode=ro', uri=True, timeout=3)
        try:
            for account, last_ts in conn.execute('SELECT account, COALESCE(last_ts, first_ts) FROM devices WHERE day = ?', (day,)):
                if last_ts >= since(account):
                    counts[account] = counts.get(account, 0) + 1
            for account, mac, count, last_ts in conn.execute('SELECT account, mac, count, last_ts FROM denied WHERE day = ? ORDER BY last_ts DESC', (day,)):
                if last_ts >= since(account):
                    denied.setdefault(account, []).append({'mac': mac, 'count': count, 'last': datetime.fromtimestamp(last_ts).strftime('%H:%M:%S')})
        finally:
            conn.close()
    except sqlite3.Error as e:
        # 第一次有人登入前資料庫還不存在
        logging.info(f'device limit query skipped: {e}')
    return counts, denied


_ingest_lock = threading.Lock()
_device_limit_lock = threading.Lock()


def open_db():
    conn = sqlite3.connect(AUTH_DB, timeout=10)
    conn.execute('CREATE TABLE IF NOT EXISTS logins (id INTEGER PRIMARY KEY, mac TEXT NOT NULL, ts INTEGER NOT NULL, ip TEXT NOT NULL, nas_ip TEXT NOT NULL)')
    conn.execute('CREATE INDEX IF NOT EXISTS logins_mac_ts ON logins (mac, ts DESC, id DESC)')
    conn.execute('CREATE TABLE IF NOT EXISTS ad_logins (id INTEGER PRIMARY KEY, account TEXT NOT NULL, ts INTEGER NOT NULL, mac TEXT NOT NULL, ip TEXT NOT NULL, nas_ip TEXT NOT NULL)')
    conn.execute('CREATE INDEX IF NOT EXISTS ad_logins_account_ts ON ad_logins (account, ts DESC, id DESC)')
    conn.execute('CREATE TABLE IF NOT EXISTS ingest_offsets (name TEXT PRIMARY KEY, offset INTEGER NOT NULL)')
    conn.execute('CREATE TABLE IF NOT EXISTS google_logins (id INTEGER PRIMARY KEY, account TEXT NOT NULL, ts INTEGER NOT NULL, mac TEXT NOT NULL, ip TEXT NOT NULL, nas_ip TEXT NOT NULL, called TEXT NOT NULL)')
    conn.execute('CREATE INDEX IF NOT EXISTS google_logins_account_ts ON google_logins (account, ts DESC, id DESC)')
    conn.execute('CREATE TABLE IF NOT EXISTS proxy_logins (id INTEGER PRIMARY KEY, account TEXT NOT NULL, ts INTEGER NOT NULL, mac TEXT NOT NULL, ip TEXT NOT NULL, nas_ip TEXT NOT NULL, called TEXT NOT NULL)')
    conn.execute('CREATE INDEX IF NOT EXISTS proxy_logins_account_ts ON proxy_logins (account, ts DESC, id DESC)')
    conn.execute('CREATE TABLE IF NOT EXISTS auth_failures (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, mac TEXT NOT NULL, account TEXT NOT NULL, '
                 'ssid TEXT NOT NULL, called TEXT NOT NULL, ip TEXT NOT NULL, nas_ip TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT NOT NULL)')
    conn.execute('CREATE INDEX IF NOT EXISTS auth_failures_ts ON auth_failures (ts DESC, id DESC)')
    create_ad_devices(conn)
    for table in ('logins', 'ad_logins'):
        if 'called' not in [row[1] for row in conn.execute(f'PRAGMA table_info({table})')]:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN called TEXT NOT NULL DEFAULT ''")
            except sqlite3.OperationalError as e:
                # 另一個執行緒剛好先加好
                if 'duplicate column' not in str(e):
                    raise
    return conn


def record_ad_device(conn, account, ts, mac):
    if mac:
        conn.execute('INSERT INTO ad_devices (account, mac, first_ts, last_ts) VALUES (?, ?, ?, ?) '
                     'ON CONFLICT (account, mac) DO UPDATE SET first_ts = MIN(first_ts, excluded.first_ts), last_ts = MAX(last_ts, excluded.last_ts)',
                     (account, mac, ts, ts))


def create_ad_devices(conn):
    """帳號用過的裝置 MAC 獨立存放，不受登入紀錄保留筆數影響。第一次建立時從現有紀錄與記錄檔補齊。"""
    exists = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ad_devices'"
    if conn.execute(exists).fetchone():
        return
    conn.execute('BEGIN IMMEDIATE')
    try:
        if not conn.execute(exists).fetchone():
            conn.execute('CREATE TABLE ad_devices (account TEXT NOT NULL, mac TEXT NOT NULL, first_ts INTEGER NOT NULL, last_ts INTEGER NOT NULL, PRIMARY KEY (account, mac))')
            for account, ts, mac in conn.execute('SELECT account, ts, mac FROM ad_logins').fetchall():
                record_ad_device(conn, account, ts, mac)
            names = os.listdir(AUTH_LOG_DIR) if os.path.isdir(AUTH_LOG_DIR) else []
            for name in sorted(name for name in names if name.startswith('ad-') and AUTH_LOG_RE.fullmatch(name)):
                with open(os.path.join(AUTH_LOG_DIR, name), 'rb') as f:
                    for raw in f.read().splitlines():
                        parsed = parse_ad_login_line(raw.decode('utf-8', 'replace'))
                        if parsed:
                            record_ad_device(conn, parsed[0], parsed[1], parsed[2])
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def clean_called(value):
    """Called-Station-Id 由 AP 送來，SSID 可含任意字元；不合理的值當作沒有。"""
    return value if re.fullmatch(r'[^\x00-\x1f\x7f]{1,128}', value) else ''


def split_called(value):
    """AA-BB-CC-DD-EE-FF:SSID 拆成 AP MAC 與 SSID，其他格式整段當 SSID 顯示。"""
    match = re.fullmatch(r'((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})(?::(.*))?', value)
    if not match:
        return '', value
    return match.group(1).upper().replace(':', '-'), match.group(2) or ''


def parse_login_line(line):
    """FreeRADIUS 寫入的欄位含裝置送來的值，不符合格式就丟棄。舊格式沒有最後的 Called-Station-Id。"""
    parts = line.split('|', 4)
    if len(parts) < 4 or not re.fullmatch(r'[0-9]{1,12}', parts[0]):
        return None
    mac = parts[1].upper()
    if not MAC_RE.fullmatch(mac):
        return None
    try:
        ip = str(ipaddress.ip_address(parts[2]))
        nas_ip = str(ipaddress.ip_address(parts[3])) if parts[3] else ''
    except ValueError:
        return None
    return mac, int(parts[0]), ip, nas_ip, clean_called(parts[4]) if len(parts) == 5 else ''


def normalize_account(value):
    value = value.strip()
    if '\\' in value:
        value = value.rsplit('\\', 1)[1]
    if '@' in value:
        value = value.split('@', 1)[0]
    return value.lower()


def parse_ad_login_line(line):
    parts = line.split('|', 5)
    if len(parts) < 5 or not re.fullmatch(r'[0-9]{1,12}', parts[0]):
        return None
    account = normalize_account(parts[1])
    mac = parts[2].upper()
    if not ACCOUNT_RE.fullmatch(account) or (mac and not MAC_RE.fullmatch(mac)):
        return None
    try:
        ip = str(ipaddress.ip_address(parts[3]))
        nas_ip = str(ipaddress.ip_address(parts[4])) if parts[4] else ''
    except ValueError:
        return None
    return account, int(parts[0]), mac, ip, nas_ip, clean_called(parts[5]) if len(parts) == 6 else ''


def parse_google_login_line(line):
    """帳號是通過 Google 驗證的完整 email，轉小寫保存。"""
    parts = line.split('|', 5)
    if len(parts) != 6 or not re.fullmatch(r'[0-9]{1,12}', parts[0]):
        return None
    try:
        account = bytes.fromhex(parts[1]).decode('utf-8').strip().lower()
        ip = str(ipaddress.ip_address(parts[3]))
        nas_ip = str(ipaddress.ip_address(parts[4])) if parts[4] else ''
    except ValueError:
        return None
    mac = parts[2].upper()
    if not re.fullmatch(r'[^\s@|]{1,64}@[^\s@|]{1,190}', account) or (mac and not MAC_RE.fullmatch(mac)):
        return None
    return account, int(parts[0]), mac, ip, nas_ip, clean_called(parts[5])


def parse_proxy_login_line(line):
    """帳號是外部 RADIUS 驗證通過的內層帳號，格式不固定（可能含 @ 或 \\），轉小寫、去控制字元保存。"""
    parts = line.split('|', 5)
    if len(parts) != 6 or not re.fullmatch(r'[0-9]{1,12}', parts[0]):
        return None
    try:
        account = re.sub(r'[\x00-\x1f\x7f]', '', bytes.fromhex(parts[1]).decode('utf-8', 'replace')).strip().lower()[:128]
        ip = str(ipaddress.ip_address(parts[3]))
        nas_ip = str(ipaddress.ip_address(parts[4])) if parts[4] else ''
    except ValueError:
        return None
    mac = parts[2].upper()
    if not account or (mac and not MAC_RE.fullmatch(mac)):
        return None
    return account, int(parts[0]), mac, ip, nas_ip, clean_called(parts[5])


def parse_fail_line(line):
    """失敗紀錄的值都未通過驗證，FreeRADIUS 以 hex 寫入，這裡還原並去掉控制字元。"""
    parts = line.split('|')
    if len(parts) != 10 or not re.fullmatch(r'[0-9]{1,12}', parts[0]) or parts[3] not in ('mac', 'ad', 'google', 'proxy', 'reject', ''):
        return None
    try:
        ip = str(ipaddress.ip_address(parts[1]))
        nas_ip = str(ipaddress.ip_address(parts[2])) if parts[2] else ''
        mac, inner, outer, inner_reason, reason, called = [
            re.sub(r'[\x00-\x1f\x7f]', '', bytes.fromhex(value).decode('utf-8', 'replace')) for value in parts[4:]]
    except ValueError:
        return None
    mac = mac.upper().replace(':', '-')
    # 外部帳號的網域是帳號的一部分，不去掉
    account = (inner or outer).strip().lower()[:128] if parts[3] == 'proxy' else normalize_account(inner or outer)[:64]
    # 名單認證的 User-Name 就是 MAC，不是帳號
    if re.fullmatch(r'[0-9a-f]{12}', re.sub(r'[-:.]', '', account)):
        account = ''
    called = clean_called(called)
    return (int(parts[0]), mac if MAC_RE.fullmatch(mac) else '', account, split_called(called)[1], called, ip, nas_ip,
            parts[3], (inner_reason or reason)[:300])


def prune_failures(conn):
    conn.execute('DELETE FROM auth_failures WHERE ts < ?', (int(time.time()) - load_settings()['fail_retention_days'] * 86400,))


def fail_reason_label(kind, reason):
    for text, label in FAIL_REASONS:
        if text in reason:
            return label
    if not reason:
        if kind == 'google':
            return 'Google 帳號不存在或連不上 Google'
        if kind == 'proxy':
            return '外部 RADIUS 拒絕'
        return '不在放行裝置名單' if kind == 'mac' else '驗證未通過'
    return '其他'


def prune_table(conn, table, column, keys, keep):
    for key in keys:
        conn.execute(f'DELETE FROM {table} WHERE {column} = ? AND id NOT IN '
                     f'(SELECT id FROM {table} WHERE {column} = ? ORDER BY ts DESC, id DESC LIMIT ?)', (key, key, keep))


def prune_logins(conn, macs=None, accounts=None):
    keep = load_settings()['login_retention']
    if macs is None:
        macs = [row[0] for row in conn.execute('SELECT DISTINCT mac FROM logins')]
    if accounts is None:
        accounts = [row[0] for row in conn.execute('SELECT DISTINCT account FROM ad_logins')]
    prune_table(conn, 'logins', 'mac', macs, keep)
    prune_table(conn, 'ad_logins', 'account', accounts, keep)
    prune_table(conn, 'google_logins', 'account', [row[0] for row in conn.execute('SELECT DISTINCT account FROM google_logins')], keep)
    prune_table(conn, 'proxy_logins', 'account', [row[0] for row in conn.execute('SELECT DISTINCT account FROM proxy_logins')], keep)


def ingest_logins():
    """把 FreeRADIUS 的每日記錄檔匯入資料庫，每台裝置只保留設定的筆數。"""
    if not os.path.isdir(AUTH_LOG_DIR):
        return
    with _ingest_lock:
        conn = open_db()
        try:
            names = sorted(name for name in os.listdir(AUTH_LOG_DIR) if AUTH_LOG_RE.fullmatch(name))
            touched = set()
            touched_accounts = set()
            for name in names:
                row = conn.execute('SELECT offset FROM ingest_offsets WHERE name = ?', (name,)).fetchone()
                offset = row[0] if row else 0
                with open(os.path.join(AUTH_LOG_DIR, name), 'rb') as f:
                    # 檔案比上次讀到的位置還短，代表被換掉或截短過：從頭讀，否則之後寫入的行會被跳過
                    if offset > os.fstat(f.fileno()).st_size:
                        logging.warning(f'{name} is shorter than the imported offset, reading it again from the start')
                        offset = 0
                    f.seek(offset)
                    data = f.read()
                # 只處理完整的行，寫到一半的留到下一輪
                end = data.rfind(b'\n') + 1
                for raw in data[:end].splitlines():
                    line = raw.decode('utf-8', 'replace')
                    if name.startswith('proxy-'):
                        parsed = parse_proxy_login_line(line)
                        if parsed:
                            conn.execute('INSERT INTO proxy_logins (account, ts, mac, ip, nas_ip, called) VALUES (?, ?, ?, ?, ?, ?)', parsed)
                        continue
                    if name.startswith('google-'):
                        parsed = parse_google_login_line(line)
                        if parsed:
                            conn.execute('INSERT INTO google_logins (account, ts, mac, ip, nas_ip, called) VALUES (?, ?, ?, ?, ?, ?)', parsed)
                        continue
                    if name.startswith('fail-'):
                        parsed = parse_fail_line(line)
                        if parsed:
                            conn.execute('INSERT INTO auth_failures (ts, mac, account, ssid, called, ip, nas_ip, kind, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', parsed)
                        continue
                    if name.startswith('ad-'):
                        parsed = parse_ad_login_line(line)
                        if parsed:
                            conn.execute('INSERT INTO ad_logins (account, ts, mac, ip, nas_ip, called) VALUES (?, ?, ?, ?, ?, ?)', parsed)
                            record_ad_device(conn, parsed[0], parsed[1], parsed[2])
                            touched_accounts.add(parsed[0])
                        continue
                    parsed = parse_login_line(line)
                    if parsed:
                        conn.execute('INSERT INTO logins (mac, ts, ip, nas_ip, called) VALUES (?, ?, ?, ?, ?)', parsed)
                        touched.add(parsed[0])
                conn.execute('INSERT OR REPLACE INTO ingest_offsets (name, offset) VALUES (?, ?)', (name, offset + end))
            prune_logins(conn, touched, touched_accounts)
            prune_failures(conn)
            conn.commit()
            # 今天與昨天的檔案可能還會寫入，更舊的已匯入完就刪除
            cutoff = (datetime.now() - timedelta(days=1)).strftime('%Y%m%d')
            for name in names:
                if AUTH_LOG_RE.fullmatch(name).group(2) < cutoff:
                    os.unlink(os.path.join(AUTH_LOG_DIR, name))
                    conn.execute('DELETE FROM ingest_offsets WHERE name = ?', (name,))
            conn.commit()
        finally:
            conn.close()


def load_ad_accounts():
    """root 的 flask-radius-ad-status 每 5 分鐘產生。回傳 (帳號清單, 更新時間)，取不到就是 ([], None)。"""
    try:
        with open(AD_STATUS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return sorted(data['accounts'], key=lambda u: u['account'].lower()), data['time']
    except (OSError, ValueError, KeyError) as e:
        logging.warning(f'AD accounts unavailable: {e}')
        return [], None


def refresh_ad_accounts():
    """服務沒有權限查 AD，寫觸發檔讓 flask-radius-ad-status.path 啟動查詢，再等結果。回傳 recent、ok 或 timeout。"""
    _, before = load_ad_accounts()
    if before and time.time() - before < AD_REFRESH_MIN_AGE:
        return 'recent'
    with open(AD_REFRESH_FILE, 'w', encoding='utf-8') as f:
        f.write(str(time.time()))
    deadline = time.time() + AD_REFRESH_WAIT
    while time.time() < deadline:
        time.sleep(0.5)
        if load_ad_accounts()[1] != before:
            return 'ok'
    return 'timeout'


def load_group_policy():
    """沒有設定檔或內容有誤就是不限制，FreeRADIUS 端的判斷也一樣。"""
    policy = {source: {'enforce': False, 'allowed': []} for source in GROUP_SOURCES}
    try:
        with open(GROUP_POLICY_FILE, encoding='utf-8') as f:
            data = json.load(f)
        for source in GROUP_SOURCES:
            policy[source] = {'enforce': bool(data[source]['enforce']), 'allowed': [str(item) for item in data[source]['allowed']]}
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return policy


def load_blacklist():
    """回傳 ({'ad': [...], 'google': [...]}, 錯誤訊息)。檔案損毀時 FreeRADIUS 會放行所有人，所以要在頁面上警告。"""
    blacklist = {source: [] for source in GROUP_SOURCES}
    try:
        with open(BLACKLIST_FILE, encoding='utf-8') as f:
            data = json.load(f)
        for source in GROUP_SOURCES:
            blacklist[source] = [str(item) for item in data[source]]
    except FileNotFoundError:
        pass
    except (OSError, ValueError, KeyError, TypeError) as e:
        logging.error(f'blacklist unreadable: {e}')
        return blacklist, '黑名單檔案無法讀取，目前 RADIUS 不會擋任何黑名單帳號，請重新儲存黑名單。'
    return blacklist, ''


def blacklist_key(source, value):
    """AD 去掉網域、小寫；Google 是完整 email、小寫。格式不對回傳 None。"""
    value = value.strip()
    if source == 'ad':
        key = normalize_account(value)
        return key if ACCOUNT_RE.fullmatch(key) and ' ' not in key else None
    key = value.lower()
    return key if GOOGLE_EMAIL_RE.fullmatch(key) else None


def blacklist_view(source):
    blacklist, error = load_blacklist()
    return {'source': source, 'names': blacklist[source], 'error': error,
            'label': 'AD 帳號' if source == 'ad' else 'Google 帳號（完整 email）'}


def load_proxy_info():
    """外部 RADIUS 的位址與連接埠（不含共用金鑰，金鑰只在 root helper）。沒有設定回傳 None。"""
    try:
        with open(PROXY_INFO_FILE, encoding='utf-8') as f:
            info = json.load(f)
        return {'server': str(info['server']), 'port': int(info['port']), 'updated': str(info.get('updated', ''))}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def load_proxy_filter():
    """回傳 (設定, 錯誤訊息)。FreeRADIUS 讀不到這個檔案時 Proxy SSID 會全部拒絕，所以要在頁面上警告。"""
    config = {'enabled': False, 'whitelist': [], 'blacklist': [], 'outer': 'PEAP', 'inner': 'MSCHAPv2'}
    try:
        with open(PROXY_FILTER_FILE, encoding='utf-8') as f:
            data = json.load(f)
        method = (data.get('outer', 'PEAP'), data.get('inner', 'MSCHAPv2'))
        if method not in PROXY_METHODS:
            raise ValueError(f'bad method {method}')
        config = {'enabled': data.get('enabled') is True, 'whitelist': [str(w) for w in data['whitelist']],
                  'blacklist': [str(w) for w in data['blacklist']], 'outer': method[0], 'inner': method[1]}
    except FileNotFoundError:
        pass
    except (OSError, ValueError, KeyError, TypeError) as e:
        logging.error(f'proxy filter unreadable: {e}')
        return config, '黑白名單檔案無法讀取，Proxy SSID 的登入目前會全部被拒絕，請重新儲存黑白名單。'
    return config, ''


def proxy_filter_decide(config, account):
    """與 radius-proxy-filter 相同的判斷，供頁面預覽。"""
    if not config['enabled']:
        return 'off'
    name = account.strip().lower()
    if any(word.lower() in name for word in config['blacklist'] if word):
        return 'blacklist'
    whitelist = [word.lower() for word in config['whitelist'] if word]
    if whitelist and not any(word in name for word in whitelist):
        return 'notlisted'
    return 'allow'


def parse_proxy_keywords(text):
    """回傳 (關鍵字清單, 錯誤訊息)。一行一個，不分大小寫，重複的只留一個。"""
    words, seen = [], set()
    for line in text.splitlines():
        word = line.strip()
        if not word:
            continue
        if len(word) > 64 or not word.isprintable() or '|' in word:
            return [], f'關鍵字必須是 1 到 64 個可見字元，不可含 |：{word[:40]}'
        if word.lower() not in seen:
            seen.add(word.lower())
            words.append(word)
    if len(words) > MAX_PROXY_KEYWORDS:
        return [], f'關鍵字最多 {MAX_PROXY_KEYWORDS} 個'
    return words, ''


def google_ancestors(path):
    """「四年級/A班」回傳最上層、「四年級」與「四年級/A班」；勾選上層機構就包含底下的子機構。"""
    parts = path.split('/') if path else []
    return ['/'.join(parts[:depth]) for depth in range(len(parts) + 1)]


def load_google_directory():
    try:
        with open(GOOGLE_DIR_FILE, encoding='utf-8') as f:
            data = json.load(f)
        return data['users'], data['ous'], data['time']
    except (OSError, ValueError, KeyError) as e:
        logging.info(f'Google directory unavailable: {e}')
        return [], [], None


def group_directory(source):
    """回傳 (選項 [{id, label}], 每個選項的成員集合, 全部成員集合, 更新時間)。AD 計算全部帳號，含已停用的。"""
    if source == 'ad':
        try:
            with open(AD_STATUS_FILE, encoding='utf-8') as f:
                data = json.load(f)
            accounts, groups, updated = data['accounts'], data['groups'], data['time']
        except (OSError, ValueError, KeyError) as e:
            logging.warning(f'AD groups unavailable: {e}')
            return [], {}, set(), None
        members = {group['sid']: set() for group in groups}
        for user in accounts:
            for sid in user.get('groups', []):
                members.setdefault(sid, set()).add(normalize_account(user['account']))
        options = [{'id': group['sid'], 'label': group['name']} for group in groups]
        return options, members, {normalize_account(user['account']) for user in accounts}, updated
    users, ous, updated = load_google_directory()
    members = {path: set() for path in ous}
    for user in users:
        for path in google_ancestors(user['ou']):
            members.setdefault(path, set()).add(user['email'].lower())
    # 最上層包含所有人，只有真的有人直接放在最上層時才列出來
    direct_root = any(not user['ou'] for user in users)
    options = [{'id': path, 'label': path or GOOGLE_ROOT_LABEL} for path in members if path or direct_root]
    return options, members, {user['email'].lower() for user in users}, updated


def group_allowed_members(enforce, allowed, members, everyone):
    if not enforce:
        return set(everyone)
    return set().union(*(members.get(item, set()) for item in allowed)) if allowed else set()


def group_policy_view(source):
    """ad.html、google.html 共用的 Wi-Fi 限制區塊。有成員的排前面，AD 內建群組多半是空的。"""
    options, members, everyone, updated = group_directory(source)
    policy = load_group_policy()[source]
    rows = [{**option, 'count': len(members.get(option['id'], ())), 'checked': option['id'] in policy['allowed']} for option in options]
    rows.sort(key=lambda row: (row['count'] == 0, row['label']))
    stale_after = AD_STATUS_STALE if source == 'ad' else GOOGLE_DIR_STALE
    return {'source': source, **GROUP_SOURCES[source], 'rows': rows, 'enforce': policy['enforce'], 'total': len(everyone),
            'checked_count': sum(row['checked'] for row in rows),
            'allowed_count': len(group_allowed_members(policy['enforce'], policy['allowed'], members, everyone)),
            'updated': datetime.fromtimestamp(updated).strftime('%Y-%m-%d %H:%M:%S') if updated else '',
            'stale': bool(updated and time.time() - updated > stale_after)}


def ingest_loop():
    while True:
        try:
            ingest_logins()
        except Exception:
            logging.exception('login ingest failed')
        time.sleep(INGEST_INTERVAL)


def is_valid_id(entry_id):
    return bool(ID_RE.fullmatch(entry_id))


def is_valid_mac(mac):
    return bool(MAC_RE.fullmatch(mac))


def is_valid_number(value, low, high):
    return bool(re.fullmatch(r'[0-9]{1,4}', value)) and low <= int(value) <= high


def attrs_errors(tunnel_type, tunnel_medium, tunnel_group):
    errors = []
    if not is_valid_number(tunnel_type, 1, 32):
        errors.append('Tunnel-Type 必須是 1 到 32 的數字')
    if not is_valid_number(tunnel_medium, 1, 32):
        errors.append('Medium-Type 必須是 1 到 32 的數字')
    if not is_valid_number(tunnel_group, 1, 4094):
        errors.append('VLAN (Group-ID) 必須是 1 到 4094 的數字')
    return errors


def find_duplicates(entries):
    by_id = {}
    by_mac = {}
    for e in entries:
        by_id.setdefault(e['id'].lower(), []).append(e)
        by_mac.setdefault(e['mac'], []).append(e)
    return {
        'ids': [group for group in by_id.values() if len(group) > 1],
        'macs': [group for group in by_mac.values() if len(group) > 1]
    }


def source_allowed(address, cidrs):
    """沒有設定就不限制。本機一律放行：部署檢查與救援都從本機連線，能到這一步的人已經有主機權限。"""
    if not cidrs:
        return True
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    ip = getattr(ip, 'ipv4_mapped', None) or ip
    if ip.is_loopback:
        return True
    for cidr in cidrs:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


@app.before_request
def restrict_source_ip():
    # 服務直接對外，沒有經過 proxy，remote_addr 就是真實來源；不可改看 X-Forwarded-For，那可以偽造
    if not source_allowed(request.remote_addr, load_settings().get('allowed_cidrs', [])):
        return Response('此來源 IP 不允許連線到管理介面\n', status=403, mimetype='text/plain')
    return None


@app.before_request
def reject_cross_site_post():
    # 瀏覽器一定會帶這兩個標頭，跨站送出的表單到不了後面的路由
    if request.method != 'POST':
        return None
    origin = request.headers.get('Origin')
    if (origin and urlsplit(origin).netloc != request.host) or request.headers.get('Sec-Fetch-Site') == 'cross-site':
        return Response('不接受來自其他網站的請求\n', status=403, mimetype='text/plain')
    return None


@app.before_request
def require_setup():
    """初始化完成前，只開放精靈與靜態檔。"""
    if load_settings().get('setup_done') or request.endpoint == 'static' or request.path.startswith('/setup'):
        return None
    if load_env().get('ADMIN_PASSWORD_HASH') and request.path in ('/login', '/logout'):
        return None
    return redirect('/setup')


@app.after_request
def security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # 不可用 no-referrer：瀏覽器的表單 POST 會變成 Origin: null，被上面的跨站檢查擋下
    response.headers['Referrer-Policy'] = 'same-origin'
    if request.path.startswith('/setup') or request.path.startswith('/settings'):
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.context_processor
def inject_site():
    return {'base': request.script_root, 'org_name': load_settings().get('org_name', ''), 'app_version': app_version(),
            'ad_enabled': load_settings().get('ad_enabled', False), 'google_enabled': load_settings().get('google_enabled', False)}


def parse_cidrs(text):
    """回傳（正規化後的清單, 錯誤訊息）。可用換行、逗號或空白分隔，單一 IP 視為 /32 或 /128。"""
    cidrs = []
    for item in re.split(r'[\s,，]+', text.strip()):
        if not item:
            continue
        try:
            cidr = str(ipaddress.ip_network(item, strict=False))
        except ValueError:
            return [], f'不是正確的 IP 或 CIDR：{item}'
        if cidr not in cidrs:
            cidrs.append(cidr)
    if len(cidrs) > MAX_ALLOWED_CIDRS:
        return [], f'最多 {MAX_ALLOWED_CIDRS} 筆'
    return cidrs, None


def require_login(f):
    def wrapper(*args, **kwargs):
        if 'user' not in session or session.get('cred') != credential_tag(load_env()):
            session.clear()
            return redirect('/login')
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def plan_entry(form, entries):
    """依單筆表單計算變更。回傳 (errors, op, before, after, new_entries)。"""
    op = form.get('op', '')
    if op == 'add':
        new_id = form.get('id', '').strip()
        new_mac = normalize_mac(form.get('mac', ''))
        errors = []
        if not is_valid_id(new_id):
            errors.append('裝置名稱只能使用英數字與 _ . -（最多 64 字）')
        if not is_valid_mac(new_mac):
            errors.append('MAC 格式錯誤，範例：AA-BB-CC-DD-EE-FF')
        for e in entries:
            if e['id'].lower() == new_id.lower():
                errors.append(f"裝置名稱已存在：{e['id']}（{e['mac']}）")
            if e['mac'] == new_mac:
                errors.append(f"MAC 已存在：{e['mac']}（{e['id']}）")
        after = {'id': new_id, 'mac': new_mac, 'modified': '', **default_attrs()}
        return errors, op, None, after, entries + [after]

    index = next((i for i, e in enumerate(entries) if e['mac'] == form.get('key', '')), None)
    if index is None:
        return ['找不到這筆資料，可能已被變更，請重新整理'], op, None, None, entries
    before = entries[index]

    if op == 'delete':
        return [], op, before, None, entries[:index] + entries[index + 1:]

    if op != 'edit':
        return ['不支援的操作'], op, before, None, entries

    new_id = form.get('id', '').strip()
    new_mac = normalize_mac(form.get('mac', ''))
    tunnel_type = form.get('tunnel_type', '').strip()
    tunnel_medium = form.get('tunnel_medium', '').strip()
    tunnel_group = form.get('tunnel_group', '').strip()
    errors = []
    if not is_valid_id(new_id):
        errors.append('裝置名稱只能使用英數字與 _ . -（最多 64 字）')
    if not is_valid_mac(new_mac):
        errors.append('MAC 格式錯誤，範例：AA-BB-CC-DD-EE-FF')
    errors += attrs_errors(tunnel_type, tunnel_medium, tunnel_group)
    if errors:
        return errors, op, before, None, entries
    after = {'id': new_id, 'mac': new_mac, 'modified': before['modified'],
             'tunnel_type': str(int(tunnel_type)), 'tunnel_medium': str(int(tunnel_medium)),
             'tunnel_group': str(int(tunnel_group))}
    # 既有的重複不擋編輯其他欄位，只擋這次改出來的新重複
    for i, e in enumerate(entries):
        if i == index:
            continue
        if new_id.lower() != before['id'].lower() and e['id'].lower() == new_id.lower():
            errors.append(f"裝置名稱已存在：{e['id']}（{e['mac']}）")
        if new_mac != before['mac'] and e['mac'] == new_mac:
            errors.append(f"MAC 已存在：{e['mac']}（{e['id']}）")
    if not errors and not entry_diff(before, after):
        errors.append('沒有任何變更')
    return errors, op, before, after, entries[:index] + [after] + entries[index + 1:]


def preview_payload(op, before, after, version):
    changes = []
    if op == 'edit':
        for field, (old, new) in entry_diff(before, after).items():
            changes.append({'label': FIELD_LABELS[field], 'before': old, 'after': new})
    source = after if op == 'add' else before
    details = [{'label': FIELD_LABELS[f], 'value': source[f]} for f in FIELD_LABELS]
    return {'ok': True, 'op': op, 'changes': changes, 'details': details, 'version': version}


@app.route('/')
@require_login
def index():
    entries, version, problems = read_list()
    last_logins = {}
    try:
        ingest_logins()
        conn = open_db()
        try:
            last_logins = dict(conn.execute('SELECT mac, MAX(ts) FROM logins GROUP BY mac').fetchall())
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as e:
        # 登入紀錄有問題不能影響名單管理
        logging.warning(f'last login query failed: {e}')
    for e in entries:
        last = last_logins.get(e['mac'])
        e['last'] = datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M:%S') if last else ''
    return render_template('index.html', entries=entries, duplicates=find_duplicates(entries),
                           problems=problems, defaults=default_attrs())


@app.route('/entry/preview', methods=['POST'])
@require_login
def entry_preview():
    entries, version, problems = read_list()
    if problems:
        return jsonify(ok=False, errors=['名單檔格式異常，請先查看放行裝置清單上方的資料檢核'])
    errors, op, before, after, _ = plan_entry(request.form, entries)
    if errors:
        return jsonify(ok=False, errors=errors)
    return jsonify(preview_payload(op, before, after, version))


@app.route('/entry/commit', methods=['POST'])
@require_login
def entry_commit():
    # 沒有經過確認步驟（confirmed + 預覽時的 version）一律不寫入
    if request.form.get('confirmed') != '1':
        return jsonify(ok=False, errors=['需要確認後才能執行']), 400
    with data_lock():
        entries, version, problems = read_list()
        if problems:
            return jsonify(ok=False, errors=['名單檔格式異常，請先查看放行裝置清單上方的資料檢核']), 409
        if not hmac.compare_digest(request.form.get('version', ''), version):
            return jsonify(ok=False, errors=['資料在確認期間已被變更，請重新操作']), 409
        errors, op, before, after, new_entries = plan_entry(request.form, entries)
        if errors:
            return jsonify(ok=False, errors=errors), 400
        stamp = now_text()
        if after:
            after['modified'] = stamp
        touched = [after['mac']] if after else []
        removed = [before['mac']] if before and (not after or after['mac'] != before['mac']) else []
        record = {
            'before': public_entry(before) if before else None,
            'after': public_entry(after) if after else None,
            'changes': entry_diff(before, after) if before and after else None
        }
        backup = commit(op.upper(), new_entries, touched, removed, [record], stamp)
    logging.info(f"{op.upper()} - MAC: {(after or before)['mac']} | User: {session.get('user')} | Backup: {backup}")
    names = {'add': '新增', 'edit': '修改', 'delete': '刪除'}
    flash(f"已{names[op]} {(after or before)['id']}（{(after or before)['mac']}）", 'success')
    return jsonify(ok=True)


@app.route('/entry/logins')
@require_login
def entry_logins():
    mac = normalize_mac(request.args.get('mac', ''))
    if not is_valid_mac(mac):
        return jsonify(ok=False, errors=['MAC 格式錯誤']), 400
    ingest_logins()
    retention = load_settings()['login_retention']
    conn = open_db()
    try:
        rows = conn.execute('SELECT ts, ip, nas_ip, called FROM logins WHERE mac = ? ORDER BY ts DESC, id DESC LIMIT ?', (mac, retention)).fetchall()
    finally:
        conn.close()
    index = ap_index()
    return jsonify(ok=True, retention=retention, rows=[
        {'time': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'), 'ip': ip, 'nas_ip': nas_ip,
         'ap_name': ap_name_for(called, ip, nas_ip, index),
         'ap_mac': split_called(called)[0], 'ssid': split_called(called)[1]} for ts, ip, nas_ip, called in rows])


@app.route('/ad')
@require_login
def ad_users():
    selected = request.args.get('status')
    if selected not in ('all', 'enabled', 'disabled'):
        selected = 'enabled'
    if request.args.get('refresh') == '1':
        result = refresh_ad_accounts()
        if result == 'ok':
            flash('已重新查詢 AD', 'success')
        elif result == 'recent':
            flash('資料剛更新過，30 秒內不需要重新查詢', 'success')
        else:
            flash('重新查詢 AD 逾時，顯示的是上一次的資料', 'error')
        return redirect(f'/ad?status={selected}')
    ingest_logins()
    conn = open_db()
    try:
        stats = {row[0]: row[1] for row in conn.execute('SELECT account, MAX(ts) FROM ad_logins GROUP BY account')}
        devices = {}
        for account, mac, last_ts in conn.execute('SELECT account, mac, last_ts FROM ad_devices ORDER BY last_ts DESC, mac'):
            stamp = datetime.fromtimestamp(last_ts).strftime('%Y-%m-%d %H:%M:%S')
            devices.setdefault(account, []).append({'mac': mac, 'last': stamp})
    finally:
        conn.close()
    users, status_time = load_ad_accounts()
    rows = []
    counts = {'all': 0, 'enabled': 0, 'disabled': 0, 'missing': 0}
    seen = set()
    for user in users:
        key = normalize_account(user['account'])
        seen.add(key)
        last = stats.get(key)
        state = 'disabled' if user['disabled'] else 'enabled'
        counts['all'] += 1
        counts[state] += 1
        rows.append({'ou': '', **user, 'state': state, 'macs': devices.get(key, []),
                     'last': datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M:%S') if last else ''})
    # 帳號從 AD 刪除後，仍要能用 MAC 查到是誰。取不到 AD 資料時不判斷，否則全部都會變成「不在 AD」。
    for account in sorted(set(devices) - seen) if users else []:
        last = stats.get(account)
        counts['all'] += 1
        counts['missing'] += 1
        rows.append({'account': account, 'ou': '', 'name': '', 'disabled': False, 'state': 'missing', 'macs': devices[account],
                     'last': datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M:%S') if last else devices[account][0]['last']})
    shown_count = sum(1 for row in rows if selected == 'all' or row['state'] == selected)
    limit = load_device_limit()
    today_counts, today_denied = device_limit_current(limit)
    window_start, window_end = device_window(limit['window_hours'])
    blacklist = blacklist_view('ad')
    blocked = set(blacklist['names'])
    for row in rows:
        key = normalize_account(row['account'])
        row.update(today=today_counts.get(key, 0), denied=today_denied.get(key, []), exempt=key in limit['exempt'],
                   blacklisted=key in blocked, key=key)
    updated = datetime.fromtimestamp(status_time).strftime('%Y-%m-%d %H:%M:%S') if status_time else ''
    # 其他狀態的帳號也輸出（隱藏），搜尋 MAC 時才能提示它不在目前的篩選內
    return render_template('ad.html', group_policy=group_policy_view('ad'), blacklist=blacklist, users=rows, shown_count=shown_count, q=request.args.get('q', '')[:64], defaults=default_attrs(),
                           device_limit=limit['limit'], denied_accounts=len(today_denied),
                           window_hours=limit['window_hours'], window_start=window_start.strftime('%H:%M'),
                           window_end=window_end.strftime('%m-%d %H:%M'),
                           selected=selected, counts=counts, status_updated=updated,
                           status_stale=bool(status_time and time.time() - status_time > AD_STATUS_STALE))


@app.route('/ad/group')
@require_login
def ad_group_members():
    sid = request.args.get('id', '')
    options, members, _, _ = group_directory('ad')
    label = next((option['label'] for option in options if option['id'] == sid), None)
    if label is None:
        flash('找不到這個群組，資料可能已更新', 'error')
        return redirect('/ad')
    users, _ = load_ad_accounts()
    blocked = set(load_blacklist()[0]['ad'])
    rows = [{'primary': user['account'], 'name': user['name'], 'ou': user.get('ou', ''), 'disabled': user['disabled'],
             'blacklisted': normalize_account(user['account']) in blocked}
            for user in users if normalize_account(user['account']) in members.get(sid, ())]
    return render_template('group_members.html', title=f'AD 群組：{label}', back='/ad', primary_label='帳號', rows=rows, show_state=True)


@app.route('/google/ou')
@require_login
def google_ou_members():
    path = request.args.get('id', '')
    options, _, _, _ = group_directory('google')
    label = next((option['label'] for option in options if option['id'] == path), None)
    if label is None:
        flash('找不到這個機構，資料可能已更新', 'error')
        return redirect('/google')
    users, _, _ = load_google_directory()
    blocked = set(load_blacklist()[0]['google'])
    rows = sorted(({'primary': user['email'], 'name': user['name'], 'ou': user['ou'] or GOOGLE_ROOT_LABEL, 'disabled': False,
                    'blacklisted': user['email'].lower() in blocked}
                   for user in users if path in google_ancestors(user['ou'])), key=lambda row: row['primary'].lower())
    return render_template('group_members.html', title=f'Google 機構：{label}', back='/google', primary_label='Email', rows=rows, show_state=False)


@app.route('/group-policy/<source>', methods=['POST'])
@require_login
def group_policy_save(source):
    if source not in GROUP_SOURCES:
        abort(404)
    info = GROUP_SOURCES[source]
    options, members, everyone, _ = group_directory(source)
    if not options:
        flash(f'目前取不到{info["item"]}資料，無法變更', 'error')
        return redirect(info['page'])
    enforce = request.form.get('enforce') == '1'
    wanted = set(request.form.getlist('allowed'))
    selected = [option for option in options if option['id'] in wanted]
    allowed = [option['id'] for option in selected]
    with data_lock():
        policy = load_group_policy()
        before = policy[source]
        before_members = group_allowed_members(before['enforce'], before['allowed'], members, everyone)
        after_members = group_allowed_members(enforce, allowed, members, everyone)
        if request.form.get('confirmed') != '1':
            return render_template('group_policy_preview.html', info=info, source=source, enforce=enforce, selected=selected, total=len(everyone),
                                   after_count=len(after_members), lost=len(before_members - after_members), gained=len(after_members - before_members))
        policy[source] = {'enforce': enforce, 'allowed': allowed}
        save_radius_json(GROUP_POLICY_FILE, policy)
        log_change({'op': 'GROUP_POLICY', 'source': source, 'before': before, 'after': policy[source]})
    flash(f'已儲存 Wi-Fi 限制，下一次登入生效：可使用 {len(after_members)} / {len(everyone)} {info["member"]}', 'success')
    return redirect(info['page'])


@app.route('/blacklist/<source>', methods=['POST'])
@require_login
def blacklist_save(source):
    """整份清單（textarea）或單一帳號加入／移出。"""
    if source not in GROUP_SOURCES:
        abort(404)
    page = GROUP_SOURCES[source]['page']
    target = request.form.get('back', '')
    target = target if target.startswith(page) and not target.startswith('//') else page
    action = request.form.get('action', 'save')
    with data_lock():
        blacklist, _ = load_blacklist()
        before = list(blacklist[source])
        if action == 'save':
            names, bad = [], []
            for line in request.form.get('names', '').splitlines():
                if not line.strip():
                    continue
                key = blacklist_key(source, line)
                if key is None:
                    bad.append(line.strip()[:80])
                elif key not in names:
                    names.append(key)
            if bad:
                flash('黑名單未儲存，格式錯誤：' + '、'.join(bad[:10]) + ('（Google 帳號要填完整 email）' if source == 'google' else ''), 'error')
                return redirect(target)
        else:
            key = blacklist_key(source, request.form.get('account', ''))
            if key is None or action not in ('add', 'remove'):
                flash('帳號格式錯誤', 'error')
                return redirect(target)
            names = [name for name in before if name != key] + ([key] if action == 'add' else [])
        if len(names) > MAX_BLACKLIST:
            flash(f'黑名單最多 {MAX_BLACKLIST} 個帳號', 'error')
            return redirect(target)
        if names == before:
            flash('黑名單沒有變更', 'success')
            return redirect(target)
        blacklist[source] = sorted(names) if action == 'save' else names
        try:
            save_radius_json(BLACKLIST_FILE, blacklist)
        except OSError as e:
            logging.error(f'save blacklist failed: {e}')
            flash('無法儲存黑名單，未變更', 'error')
            return redirect(target)
        added = sorted(set(names) - set(before))
        removed = sorted(set(before) - set(names))
        log_change({'op': 'BLACKLIST', 'source': source, 'added': added, 'removed': removed})
    logging.info(f"BLACKLIST {source} +{added} -{removed} | User: {session.get('user')}")
    parts = ([f'加入 {len(added)} 個'] if added else []) + ([f'移出 {len(removed)} 個'] if removed else [])
    flash(f'黑名單已更新（{"、".join(parts)}），下一次登入生效；已連線的裝置不會斷線', 'success')
    return redirect(target)


PROXY_FILTER_LABELS = {'allow': '可轉送', 'blacklist': '符合黑名單', 'notlisted': '不在白名單', 'off': '未設定'}


def proxy_source_ip(info):
    """本機連到外部 RADIUS 時用的來源 IP（外部要把它加入用戶端）。只做路由查詢，不送封包。"""
    try:
        family = socket.AF_INET6 if ':' in info['server'] else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((info['server'], info['port']))
            return sock.getsockname()[0]
    except OSError:
        return ''


def proxy_page(res=None, values=None, status=200):
    ingest_logins()
    info = load_proxy_info()
    config, filter_error = load_proxy_filter()
    rules = load_ssid_rules()
    ssid_rules = [r for r in rules['rules'] if r['auth'] == 'proxy']
    conn = open_db()
    try:
        accounts = {}
        for account, mac, last, total in conn.execute('SELECT account, mac, MAX(ts), COUNT(*) FROM proxy_logins GROUP BY account, mac ORDER BY MAX(ts) DESC'):
            row = accounts.setdefault(account, {'account': account, 'last_ts': last, 'macs': [], 'logins': 0})
            row['last_ts'] = max(row['last_ts'], last)
            row['logins'] += total
            if mac:
                row['macs'].append(mac)
        fails = conn.execute("SELECT ts, mac, account, ssid, called, ip, nas_ip, kind, reason FROM auth_failures WHERE kind = 'proxy' "
                             'ORDER BY ts DESC, id DESC LIMIT ?', (PROXY_RECENT_FAILURES,)).fetchall()
    finally:
        conn.close()
    rows = sorted(accounts.values(), key=lambda row: -row['last_ts'])
    for row in rows:
        decision = proxy_filter_decide({**config, 'enabled': True}, row['account'])
        row.update(last=datetime.fromtimestamp(row['last_ts']).strftime('%Y-%m-%d %H:%M:%S'), decision=decision,
                   decision_label=PROXY_FILTER_LABELS[decision])
    index = ap_index()
    failures = [{'time': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'), 'mac': mac, 'account': account, 'ssid': ssid,
                 'ap_name': ap_name_for(called, ip, nas_ip, index), 'reason': fail_reason_label(kind, reason), 'detail': reason}
                for ts, mac, account, ssid, called, ip, nas_ip, kind, reason in fails]
    return render_template('proxy.html', info=info, source_ip=proxy_source_ip(info) if info else '', config=config, filter_error=filter_error,
                           ssid_rules=ssid_rules, default_proxy=rules['default']['auth'] == 'proxy', default_vlan=rules['default']['vlan'],
                           accounts=rows, failures=failures, res=res, values=values or {}, recent_limit=PROXY_RECENT_FAILURES,
                           methods=PROXY_METHODS, method_notes={f'{o}-{i}': note for (o, i), note in PROXY_METHOD_NOTES.items()},
                           current_note=PROXY_METHOD_NOTES[(config['outer'], config['inner'])]), status


@app.route('/proxy')
@require_login
def proxy_view():
    return proxy_page()


def set_proxy_enabled(enabled, method=None):
    with data_lock():
        config, _ = load_proxy_filter()
        if method:
            config.update(outer=method[0], inner=method[1])
        save_radius_json(PROXY_FILTER_FILE, {**config, 'enabled': enabled})


@app.route('/proxy/server', methods=['POST'])
@require_login
def proxy_server():
    form = request.form
    action = form.get('action')
    # 測試帳號與密碼不回填：只留帳號的話，下一次按測試會因為沒有密碼而失敗
    values = {'server': form.get('server', '').strip()[:253], 'port': form.get('port', '').strip()[:5],
              'outer': form.get('outer', ''), 'inner': form.get('inner', '')}
    method = (values['outer'], values['inner'])
    if action in ('save', 'test') and method not in PROXY_METHODS:
        return proxy_page({'ok': False, 'error': 'PEAP 的內層只能是 MSCHAPv2 或 GTC；要用 PAP 請選 TTLS'}, values, 400)
    test = {'test_user': form.get('test_user', '').strip(), 'test_password': form.get('test_password', ''), 'inner': values['inner']}
    if test['test_user'] and not test['test_password']:
        return proxy_page({'ok': False, 'error': '有填測試帳號時也要填測試密碼；只想測試連線與共用金鑰，請把測試帳號留白'}, values, 400)
    if action == 'test':
        return proxy_page(helper_call('proxy_test', **test), values)
    if action == 'disable':
        result = helper_call('proxy_disable')
        if result.get('ok'):
            set_proxy_enabled(False)
            try:
                os.unlink(PROXY_INFO_FILE)
            except FileNotFoundError:
                pass
            log_change({'op': 'PROXY_DISABLE'})
        return proxy_page(result)
    if action != 'save':
        abort(400)
    port = values['port'] or '1812'
    if not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
        return proxy_page({'ok': False, 'error': '連接埠必須是 1 到 65535'}, values, 400)
    result = helper_call('proxy_configure', server=values['server'], port=int(port), secret=form.get('secret', ''),
                         force=form.get('force') == '1', **test)
    if result.get('ok'):
        before = load_proxy_info()
        info = {'server': result['server'], 'port': result['port'], 'updated': now_text()}
        fd, tmp = tempfile.mkstemp(dir=STATE_DIR)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(info, f)
        os.replace(tmp, PROXY_INFO_FILE)
        old_method = load_proxy_filter()[0]
        set_proxy_enabled(True, method)
        log_change({'op': 'PROXY_CONFIG', 'before': before, 'after': info, 'secret_changed': bool(form.get('secret')),
                    'method_before': f"{old_method['outer']}-{old_method['inner']}", 'method_after': '-'.join(method)})
    return proxy_page(result, values)


@app.route('/proxy/filter', methods=['POST'])
@require_login
def proxy_filter_save():
    whitelist, error = parse_proxy_keywords(request.form.get('whitelist', ''))
    blacklist, error2 = ([], error) if error else parse_proxy_keywords(request.form.get('blacklist', ''))
    if error or error2:
        flash('黑白名單未儲存：' + (error or error2), 'error')
        return redirect('/proxy')
    with data_lock():
        config, _ = load_proxy_filter()
        before = {'whitelist': config['whitelist'], 'blacklist': config['blacklist']}
        after = {'whitelist': whitelist, 'blacklist': blacklist}
        if before == after:
            flash('黑白名單沒有變更', 'success')
            return redirect('/proxy')
        try:
            save_radius_json(PROXY_FILTER_FILE, {**config, 'enabled': bool(load_proxy_info()), **after})
        except OSError as e:
            logging.error(f'save proxy filter failed: {e}')
            flash('無法儲存黑白名單，未變更', 'error')
            return redirect('/proxy')
        log_change({'op': 'PROXY_FILTER', 'before': before, 'after': after})
    conn = open_db()
    try:
        known = [row[0] for row in conn.execute('SELECT DISTINCT account FROM proxy_logins')]
    finally:
        conn.close()
    blocked = sum(proxy_filter_decide({'enabled': True, **after}, account) != 'allow' for account in known)
    note = f'；登入過的 {len(known)} 個外部帳號中，有 {blocked} 個之後會被擋下' if known else ''
    flash(f'黑白名單已儲存，立即生效{note}', 'success')
    return redirect('/proxy')


@app.route('/ad/logins')
@require_login
def ad_logins():
    account = normalize_account(request.args.get('account', ''))
    if not ACCOUNT_RE.fullmatch(account):
        return jsonify(ok=False, errors=['帳號格式錯誤']), 400
    ingest_logins()
    retention = load_settings()['login_retention']
    conn = open_db()
    try:
        rows = conn.execute('SELECT ts, ip, mac, called, nas_ip FROM ad_logins WHERE account = ? ORDER BY ts DESC, id DESC LIMIT ?', (account, retention)).fetchall()
    finally:
        conn.close()
    index = ap_index()
    return jsonify(ok=True, retention=retention, rows=[
        {'time': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'), 'ip': ip, 'mac': mac,
         'ap_name': ap_name_for(called, ip, nas_ip, index),
         'ap_mac': split_called(called)[0], 'ssid': split_called(called)[1]} for ts, ip, mac, called, nas_ip in rows])


def settings_limit_args(limit, **overrides):
    return {'device_limit': limit['limit'], 'exempt': '\n'.join(limit['exempt']), 'max_device_limit': MAX_DEVICE_LIMIT,
            'window_hours': limit['window_hours'], 'window_choices': DEVICE_WINDOW_CHOICES,
            'next_reset': device_window(limit['window_hours'])[1].strftime('%m-%d %H:%M'),
            'fail_days': load_settings()['fail_retention_days'], 'max_fail_days': MAX_FAIL_RETENTION_DAYS, **overrides}


@app.route('/device-limit/reset', methods=['POST'])
@require_login
def device_limit_reset():
    """手動重置只寫入時間點，由檢查程式忽略這之前的裝置；資料庫由 FreeRADIUS 擁有，這裡不寫入。"""
    reset_all = request.form.get('scope') == 'all'
    account = normalize_account(request.form.get('account', ''))
    back_google = account.startswith(GOOGLE_LIMIT_PREFIX)
    status = request.form.get('status', '')
    query = request.form.get('q', '')[:64]
    target = '/settings' if reset_all else '/google' if back_google else '/ad?' + urlencode({'status': status if status in ('all', 'enabled', 'disabled') else 'enabled', 'q': query})
    if reset_all and request.form.get('confirmed') != '1':
        flash('請勾選確認後再重置全部帳號', 'error')
        return redirect(target)
    if not reset_all and not ACCOUNT_RE.fullmatch(account.removeprefix(GOOGLE_LIMIT_PREFIX)):
        flash('帳號格式錯誤', 'error')
        return redirect(target)
    # 加 1 秒：這一秒內已登入的裝置也算在重置之前
    now = int(time.time()) + 1
    midnight = int(device_window(24, now)[0].timestamp())
    with _device_limit_lock:
        limit = load_device_limit()
        # 資料以日為單位，今天以前的重置時間不會再用到
        resets = {k: v for k, v in limit['resets'].items() if v >= midnight}
        if reset_all:
            new_limit = {**limit, 'reset_all': now, 'resets': {}}
        else:
            new_limit = {**limit, 'resets': {**resets, account: now}}
        try:
            save_device_limit(new_limit)
        except OSError as e:
            logging.error(f'save device limit failed: {e}')
            flash('無法重置，裝置數未變更', 'error')
            return redirect(target)
    log_change({'op': 'DEVICE_RESET', 'account': '*' if reset_all else account})
    logging.info(f"DEVICE_RESET - {'*' if reset_all else account} | User: {session.get('user')}")
    flash('已重置全部帳號的裝置數' if reset_all else f'已重置 {account} 的裝置數', 'success')
    return redirect(target)


@app.route('/settings', methods=['GET', 'POST'])
@require_login
def settings():
    current = load_settings()
    limit = load_device_limit()
    if request.method == 'GET':
        return render_template('settings.html', retention=current['login_retention'], maximum=MAX_LOGIN_RETENTION, **settings_limit_args(limit))
    value = request.form.get('login_retention', '').strip()
    limit_value = request.form.get('device_limit', '').strip()
    exempt_text = request.form.get('exempt', '')
    window_value = request.form.get('window_hours', '').strip()
    fail_value = request.form.get('fail_retention_days', '').strip()
    form_limit = settings_limit_args(limit, device_limit=limit_value, exempt=exempt_text, fail_days=fail_value)
    exempt = sorted({normalize_account(a) for a in re.split(r'[\r\n,，]+', exempt_text) if a.strip()})
    error = None
    if not re.fullmatch(r'[0-9]{1,5}', value) or not 1 <= int(value) <= MAX_LOGIN_RETENTION:
        error = f'保留筆數必須是 1 到 {MAX_LOGIN_RETENTION} 的數字'
    elif int(value) < current['login_retention'] and request.form.get('confirm_shrink') != '1':
        error = f"調低筆數會立即刪除每台裝置、每個 AD 帳號與每個 Google 帳號超過 {int(value)} 筆的舊紀錄，請勾選確認"
    elif not re.fullmatch(r'[0-9]{1,3}', fail_value) or not 1 <= int(fail_value) <= MAX_FAIL_RETENTION_DAYS:
        error = f'驗證失敗紀錄的保留天數必須是 1 到 {MAX_FAIL_RETENTION_DAYS} 的數字'
    elif int(fail_value) < current['fail_retention_days'] and request.form.get('confirm_shrink') != '1':
        error = f'調低天數會立即刪除超過 {int(fail_value)} 天的驗證失敗紀錄，請勾選確認'
    elif not re.fullmatch(r'[0-9]{1,2}', limit_value) or int(limit_value) > MAX_DEVICE_LIMIT:
        error = f'裝置數上限必須是 0 到 {MAX_DEVICE_LIMIT} 的數字，0 表示不限制'
    elif not re.fullmatch(r'[0-9]{1,2}', window_value) or int(window_value) not in DEVICE_WINDOW_CHOICES:
        error = '重置週期不在可選擇的範圍內'
    elif len(exempt) > 200 or not all(ACCOUNT_RE.fullmatch(a.removeprefix(GOOGLE_LIMIT_PREFIX)) for a in exempt):
        error = '排除帳號格式錯誤，請一行一個帳號，最多 200 個'
    if error:
        return render_template('settings.html', retention=value, maximum=MAX_LOGIN_RETENTION, error=error, **form_limit), 400
    new_value = int(value)
    message = '設定沒有變更'
    if new_value != current['login_retention']:
        save_settings({**current, 'login_retention': new_value})
        conn = open_db()
        try:
            prune_logins(conn)
            conn.commit()
        finally:
            conn.close()
        log_change({'op': 'SETTINGS', 'login_retention': [current['login_retention'], new_value]})
        logging.info(f"SETTINGS - login_retention: {current['login_retention']} -> {new_value} | User: {session.get('user')}")
        message = '設定已更新'
    new_fail_days = int(fail_value)
    if new_fail_days != current['fail_retention_days']:
        save_settings({**load_settings(), 'fail_retention_days': new_fail_days})
        conn = open_db()
        try:
            prune_failures(conn)
            conn.commit()
        finally:
            conn.close()
        log_change({'op': 'SETTINGS', 'fail_retention_days': [current['fail_retention_days'], new_fail_days]})
        logging.info(f"SETTINGS - fail_retention_days: {current['fail_retention_days']} -> {new_fail_days} | User: {session.get('user')}")
        message = '設定已更新'
    changed = {'limit': int(limit_value), 'exempt': exempt, 'window_hours': int(window_value)}
    with _device_limit_lock:
        limit = load_device_limit()
        before = {k: limit[k] for k in changed}
        new_limit = {**limit, **changed}
        if changed != before:
            try:
                save_device_limit(new_limit)
            except OSError as e:
                logging.error(f'save device limit failed: {e}')
                return render_template('settings.html', retention=new_value, maximum=MAX_LOGIN_RETENTION,
                                       error='裝置數上限無法儲存，設定未變更', **form_limit), 500
            log_change({'op': 'SETTINGS', 'device_limit': [before, changed]})
            logging.info(f"SETTINGS - device_limit: {before} -> {changed} | User: {session.get('user')}")
            message = '設定已更新'
    return render_template('settings.html', retention=new_value, maximum=MAX_LOGIN_RETENTION, message=message, **settings_limit_args(new_limit))


def ssid_form_rules(form):
    rows = []
    for position, (order, keyword, auth, vlan) in enumerate(zip(form.getlist('order'), form.getlist('keyword'),
                                                                form.getlist('auth'), form.getlist('vlan'))):
        if keyword.strip():
            rows.append((int(order) if re.fullmatch(r'[0-9]{1,6}', order.strip()) else 999999, position,
                         {'keyword': keyword.strip(), 'auth': auth, 'vlan': vlan.strip()}))
    rules = [row[2] for row in sorted(rows, key=lambda row: row[:2])]
    return {'rules': rules, 'default': {'auth': form.get('default_auth', ''), 'vlan': form.get('default_vlan', '').strip()}}


def ssid_rule_text(rule):
    return ssid_result_text({**rule, 'vlan': rule.get('vlan', '')})


def ssid_changes(before, after):
    """規則的差異，給確認視窗用。以關鍵字（不分大小寫）對應新舊規則。"""
    old = {r['keyword'].lower(): (i, r) for i, r in enumerate(before['rules'])}
    new = {r['keyword'].lower(): (i, r) for i, r in enumerate(after['rules'])}
    changes = []
    for key, (_, rule) in new.items():
        if key not in old:
            changes.append({'kind': '新增', 'text': f"關鍵字「{rule['keyword']}」：{ssid_rule_text(rule)}"})
        else:
            prev = old[key][1]
            if (prev['auth'], prev['vlan'], prev['keyword']) != (rule['auth'], rule['vlan'], rule['keyword']):
                changes.append({'kind': '修改', 'text': f"關鍵字「{rule['keyword']}」：{ssid_rule_text(prev)} → {ssid_rule_text(rule)}"})
    for key, (_, rule) in old.items():
        if key not in new:
            changes.append({'kind': '刪除', 'text': f"關鍵字「{rule['keyword']}」（原本：{ssid_rule_text(rule)}）"})
    common_old = [k for k in old if k in new]
    common_new = sorted(common_old, key=lambda k: new[k][0])
    if sorted(common_old, key=lambda k: old[k][0]) != common_new:
        changes.append({'kind': '順序', 'text': '比對順序改為：' + ' → '.join(new[k][1]['keyword'] for k in common_new)})
    if before['default'] != after['default']:
        changes.append({'kind': '修改', 'text': f"沒有吻合任何關鍵字時：{ssid_rule_text(before['default'])} → {ssid_rule_text(after['default'])}"})
    return changes


@app.route('/ssid/preview', methods=['POST'])
@require_login
def ssid_preview_json():
    """確認視窗用：回傳更動範圍，不儲存。確認後由網頁以 confirmed=1 送到 /ssid。"""
    new = ssid_form_rules(request.form)
    error = validate_ssid_rules(new['rules'], new['default'])
    if error:
        return jsonify(ok=False, error=error)
    current = load_ssid_rules()
    if new == current:
        return jsonify(ok=True, unchanged=True)
    impact = ssid_impact(current, new)
    return jsonify(ok=True, unchanged=False, changes=ssid_changes(current, new),
                   impact=[{k: row[k] for k in ('ssid', 'before', 'after', 'warning')} for row in impact if row['changed'] or row['warning']],
                   unaffected=sum(1 for row in impact if not row['changed'] and not row['warning']), seen_days=SSID_SEEN_DAYS,
                   proxy_missing=any(r['auth'] == 'proxy' for r in [*new['rules'], new['default']]) and not load_proxy_info(),
                   rules_json=json.dumps(new, ensure_ascii=False))


def ssid_page(config, error=None, status=200):
    current = load_ssid_rules()
    rows = [{**rule, 'order': (i + 1) * 10} for i, rule in enumerate(config['rules'])]
    rows += [{'keyword': '', 'auth': 'mac', 'vlan': '', 'order': (len(rows) + i + 1) * 10} for i in range(3)]
    return render_template('ssid.html', rows=rows, default=config['default'], labels=SSID_AUTH_LABELS, error=error,
                           impact=ssid_impact(current, current), seen_days=SSID_SEEN_DAYS, max_rules=MAX_SSID_RULES), status


@app.route('/settings/ssid')
@require_login
def settings_ssid_moved():
    return redirect('/ssid')


@app.route('/ssid', methods=['GET', 'POST'])
@require_login
def ssid_rules():
    if request.method == 'GET':
        return ssid_page(load_ssid_rules())
    if request.form.get('confirmed') == '1':
        try:
            new = json.loads(request.form.get('rules_json', ''))
            rules, default = new['rules'], new['default']
            new = {'rules': [{k: str(r[k]) for k in ('keyword', 'auth', 'vlan')} for r in rules],
                   'default': {k: str(default[k]) for k in ('auth', 'vlan')}}
        except (ValueError, KeyError, TypeError):
            flash('確認資料已失效，規則未變更，請重新設定', 'error')
            return redirect('/ssid')
        error = validate_ssid_rules(new['rules'], new['default'])
        if error:
            return ssid_page(new, error, 400)
        with _device_limit_lock:
            before = load_ssid_rules()
            try:
                save_radius_json(SSID_RULES_FILE, new)
            except OSError as e:
                logging.error(f'save ssid rules failed: {e}')
                flash('無法儲存，規則未變更', 'error')
                return redirect('/ssid')
        log_change({'op': 'SSID_RULES', 'before': before, 'after': new})
        logging.info(f"SSID_RULES - {before} -> {new} | User: {session.get('user')}")
        flash('SSID 規則已儲存，下一次登入立即生效', 'success')
        return redirect('/ssid')
    new = ssid_form_rules(request.form)
    error = validate_ssid_rules(new['rules'], new['default'])
    if error:
        return ssid_page(new, error, 400)
    current = load_ssid_rules()
    if new == current:
        flash('規則沒有變更', 'success')
        return redirect('/ssid')
    proxy_missing = any(r['auth'] == 'proxy' for r in [*new['rules'], new['default']]) and not load_proxy_info()
    return render_template('ssid_preview.html', new=new, labels=SSID_AUTH_LABELS, impact=ssid_impact(current, new), proxy_missing=proxy_missing,
                           rules_json=json.dumps(new, ensure_ascii=False), seen_days=SSID_SEEN_DAYS)


def failure_filters(args, days):
    """把網址參數轉成 SQL 條件。AP 與失敗原因是查詢時才對應的名稱，先找出符合的原始值。"""
    where, params = ['ts >= ?'], [int(time.time()) - days * 86400]
    for field in ('mac', 'account', 'ssid'):
        if args.get(field) is not None:
            where.append(f'{field} = ?')
            params.append(args[field])
    if args.get('account') is not None:
        where.append(FAIL_ACCOUNT_KINDS['account'])
    for field in ('google', 'proxy'):
        if args.get(field) is not None:
            where.append(f"account = ? AND {FAIL_ACCOUNT_KINDS[field]}")
            params.append(args[field])
    if args.get('q'):
        text = args['q'].replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        compact = re.sub(r'[-:.]', '', text)
        where.append("(REPLACE(mac, '-', '') LIKE ? ESCAPE '\\' OR account LIKE ? ESCAPE '\\' OR ssid LIKE ? ESCAPE '\\')")
        params += [f'%{compact}%', f'%{text}%', f'%{text}%']
    return where, params


def narrow_failures(conn, args, where, params):
    if args.get('ap') is not None:
        index = ap_index()
        rows = conn.execute(f"SELECT DISTINCT called, ip, nas_ip FROM auth_failures WHERE {' AND '.join(where)}", params).fetchall()
        rows = [row for row in rows if ap_name_for(*row, index) == args['ap']]
        where = [*where, '(called, ip, nas_ip) IN (VALUES ' + ','.join(['(?, ?, ?)'] * len(rows)) + ')' if rows else '0']
        params = [*params, *[value for row in rows for value in row]]
    if args.get('reason') is not None:
        rows = conn.execute(f"SELECT DISTINCT kind, reason FROM auth_failures WHERE {' AND '.join(where)}", params).fetchall()
        rows = [row for row in rows if fail_reason_label(*row) == args['reason']]
        where = [*where, '(kind, reason) IN (VALUES ' + ','.join(['(?, ?)'] * len(rows)) + ')' if rows else '0']
        params = [*params, *[value for row in rows for value in row]]
    return where, params


def failure_stats(conn, group, where, params):
    condition = ' AND '.join(where)
    if group in ('mac', 'ssid'):
        rows = conn.execute(f'SELECT {group}, COUNT(*), MAX(ts) FROM auth_failures WHERE {condition} GROUP BY {group}', params).fetchall()
    elif group in FAIL_ACCOUNT_KINDS:
        rows = conn.execute(f'SELECT account, COUNT(*), MAX(ts) FROM auth_failures WHERE {condition} AND {FAIL_ACCOUNT_KINDS[group]} GROUP BY account', params).fetchall()
    else:
        columns = 'called, ip, nas_ip' if group == 'ap' else 'kind, reason'
        index = ap_index() if group == 'ap' else None
        merged = {}
        for *key, count, last in conn.execute(f'SELECT {columns}, COUNT(*), MAX(ts) FROM auth_failures WHERE {condition} GROUP BY {columns}', params):
            label = ap_name_for(*key, index) if group == 'ap' else fail_reason_label(*key)
            total, newest = merged.get(label, (0, 0))
            merged[label] = (total + count, max(newest, last))
        rows = [(label, *value) for label, value in merged.items()]
    rows.sort(key=lambda row: (-row[1], row[0]))
    return len(rows), [{'value': value, 'count': count, 'last': datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M:%S')}
                       for value, count, last in rows[:FAIL_STATS_LIMIT]]


@app.route('/google')
@require_login
def google_accounts():
    """上方是機構與 Wi-Fi 限制，下方是用 Google 帳號登入過 Wi-Fi 的人。"""
    if request.args.get('refresh') == '1':
        with open(GOOGLE_REFRESH_FILE, 'w', encoding='utf-8') as f:
            f.write(str(time.time()))
        before = load_google_directory()[2]
        deadline = time.time() + AD_REFRESH_WAIT
        while time.time() < deadline and load_google_directory()[2] == before:
            time.sleep(0.5)
        if load_google_directory()[2] == before:
            flash('重新查詢 Google 逾時，顯示的是上一次的資料', 'error')
        else:
            flash('已重新查詢 Google', 'success')
        return redirect('/google')
    ingest_logins()
    limit = load_device_limit()
    counts, denied = device_limit_current(limit)
    selected = request.args.get('account', '').strip().lower()[:254]
    conn = open_db()
    try:
        accounts = {}
        for account, mac, last, total in conn.execute('SELECT account, mac, MAX(ts), COUNT(*) FROM google_logins GROUP BY account, mac ORDER BY MAX(ts) DESC'):
            row = accounts.setdefault(account, {'account': account, 'last_ts': last, 'macs': [], 'logins': 0})
            row['last_ts'] = max(row['last_ts'], last)
            row['logins'] += total
            if mac:
                row['macs'].append(mac)
        logins = conn.execute('SELECT ts, mac, called, ip, nas_ip FROM google_logins WHERE account = ? ORDER BY ts DESC, id DESC', (selected,)).fetchall() if selected else []
    finally:
        conn.close()
    rows = sorted(accounts.values(), key=lambda row: -row['last_ts'])
    blacklist = blacklist_view('google')
    for row in rows:
        key = GOOGLE_LIMIT_PREFIX + normalize_account(row['account'])
        row.update(key=key, blacklisted=row['account'].lower() in blacklist['names'], today=counts.get(key, 0), denied=denied.get(key, []), exempt=key in limit['exempt'],
                   last=datetime.fromtimestamp(row['last_ts']).strftime('%Y-%m-%d %H:%M:%S'))
    index = ap_index()
    detail = [{'time': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'), 'mac': mac, 'ssid': split_called(called)[1],
               'ap_name': ap_name_for(called, ip, nas_ip, index)} for ts, mac, called, ip, nas_ip in logins]
    ldap_cert = helper_call('ldap_cert_info', timeout=15) if load_settings().get('google_enabled') else None
    return render_template('google.html', ldap_cert=ldap_cert, group_policy=group_policy_view('google'), blacklist=blacklist, accounts=rows, selected=selected, detail=detail, device_limit=limit['limit'])


@app.route('/failures')
@require_login
def failures():
    ingest_logins()
    retention = load_settings()['fail_retention_days']
    day_text = request.args.get('days', '')
    days = int(day_text) if re.fullmatch(r'[0-9]{1,3}', day_text) and 1 <= int(day_text) <= retention else retention
    group = request.args.get('by') if request.args.get('by') in FAIL_GROUPS else 'mac'
    args = {k: request.args[k][:128] for k in ('mac', 'account', 'google', 'proxy', 'ssid', 'ap', 'reason') if k in request.args}
    query = request.args.get('q', '').strip()[:64]
    page_text = request.args.get('page', '')
    page = int(page_text) if re.fullmatch(r'[0-9]{1,6}', page_text) and int(page_text) > 0 else 1
    where, params = failure_filters({**args, 'q': query}, days)
    conn = open_db()
    try:
        where, params = narrow_failures(conn, args, where, params)
        condition = ' AND '.join(where)
        total, macs, accounts, google_accounts, proxy_accounts = conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT NULLIF(mac, '')), "
            + ', '.join(f"COUNT(DISTINCT CASE WHEN {FAIL_ACCOUNT_KINDS[k]} THEN NULLIF(account, '') END)" for k in ('account', 'google', 'proxy'))
            + f" FROM auth_failures WHERE {condition}", params).fetchone()
        group_total, stats = failure_stats(conn, group, where, params)
        rows = conn.execute(f'SELECT ts, mac, account, ssid, called, ip, nas_ip, kind, reason FROM auth_failures WHERE {condition} '
                            'ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?', [*params, FAIL_PAGE_SIZE, (page - 1) * FAIL_PAGE_SIZE]).fetchall()
    finally:
        conn.close()
    index = ap_index()
    entries = [{'time': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'), 'mac': mac, 'ssid': ssid,
                'account': '' if kind in ('google', 'proxy') else account, 'google': account if kind == 'google' else '',
                'proxy': account if kind == 'proxy' else '',
                'ap_name': ap_name_for(called, ip, nas_ip, index), 'ap_mac': split_called(called)[0], 'ip': ip,
                'reason': fail_reason_label(kind, reason), 'detail': reason}
               for ts, mac, account, ssid, called, ip, nas_ip, kind, reason in rows]
    state = {'days': days, 'by': group, **args, **({'q': query} if query else {})}

    def link(**changes):
        merged = {**state, **changes}
        return request.script_root + '/failures?' + urlencode({k: v for k, v in merged.items() if v is not None})
    choices = sorted({d for d in (1, 7, 14, 30, 90, 180, 365) if d <= retention} | {retention})
    return render_template('failures.html', entries=entries, stats=stats, group=group, groups=FAIL_GROUPS, group_total=group_total,
                           total=total, macs=macs, accounts=accounts, google_accounts=google_accounts, proxy_accounts=proxy_accounts, days=days, day_choices=choices, retention=retention,
                           filters=[(k, FAIL_GROUPS[k], v) for k, v in args.items()], q=query, link=link, page=page,
                           has_next=page * FAIL_PAGE_SIZE < total, stats_limit=FAIL_STATS_LIMIT)


# ---- 版本更新 ----
UPDATE_STATUS_FILE = os.path.join(STATE_DIR, 'update-status.json')
EXPORT_FILE_DIR = os.path.join(STATE_DIR, 'exports')
UPDATE_TIMEOUT = 120


def project_info():
    try:
        with open(os.path.join(APP_ROOT, 'project.json'), encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {'name': 'freeradius-woofweb', 'author': '', 'github': '', 'license': ''}


def reauth_error(password):
    """更新、回溯、匯出前再確認一次管理者密碼，失敗次數與登入共用鎖定。"""
    address = request.remote_addr
    if login_locked(address):
        return f'失敗次數過多，請 {LOGIN_LOCK_SECONDS // 60} 分鐘後再試'
    if check_password_hash(load_env().get('ADMIN_PASSWORD_HASH', ''), password or ''):
        login_clear(address)
        return ''
    login_failed(address)
    logging.warning(f'reauth failed: {address}')
    return '管理者密碼錯誤'


@app.route('/update')
@require_login
def update_page():
    return render_template('update.html', project=project_info(), version=app_version())


@app.route('/update/check', methods=['POST'])
@require_login
def update_check():
    return jsonify(helper_call('update_check', timeout=UPDATE_TIMEOUT))


@app.route('/update/key', methods=['POST'])
@require_login
def update_key():
    result = helper_call('update_key')
    if result.get('ok'):
        log_change({'op': 'UPDATE_KEY'})
    return jsonify(result)


@app.route('/update/verify', methods=['POST'])
@require_login
def update_verify():
    result = helper_call('update_verify', timeout=UPDATE_TIMEOUT)
    if result.get('ok'):
        log_change({'op': 'UPDATE_VERIFY', 'version': result.get('version'), 'differences': len(result.get('differences', [])),
                    'links': len(result.get('links', []))})
    return jsonify(result)


@app.route('/update/backups', methods=['POST'])
@require_login
def update_backups():
    return jsonify(helper_call('update_backups'))


@app.route('/update/start', methods=['POST'])
@require_login
def update_start():
    error = reauth_error(request.form.get('password'))
    if error:
        return jsonify(ok=False, error=error)
    kind = request.form.get('kind', '')
    params = {'kind': kind, 'version': request.form.get('version', ''), 'backup': request.form.get('backup', '')}
    result = helper_call('update_start', timeout=UPDATE_TIMEOUT, **params)
    log_change({'op': 'UPDATE_START' if kind == 'update' else 'UPDATE_ROLLBACK', 'from': app_version(),
                'target': params['version'] or params['backup'], 'ok': bool(result.get('ok')), 'error': result.get('error', '')})
    return jsonify(result)


@app.route('/update/status')
@require_login
def update_status():
    try:
        with open(UPDATE_STATUS_FILE, encoding='utf-8') as f:
            status = json.load(f)
    except (OSError, ValueError):
        status = {'state': 'none'}
    return jsonify(ok=True, version=app_version(), **status)


@app.route('/update/export', methods=['POST'])
@require_login
def update_export():
    error = reauth_error(request.form.get('password'))
    if error:
        return jsonify(ok=False, error=error), 403
    result = helper_call('config_export')
    name = result.get('file', '')
    if not result.get('ok') or not re.fullmatch(r'freeradius-woofweb-config-[A-Za-z0-9.-]+\.tar\.gz', name):
        return jsonify(ok=False, error=result.get('error', '匯出失敗')), 500
    path = os.path.join(EXPORT_FILE_DIR, name)
    try:
        with open(path, 'rb') as f:
            data = f.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    log_change({'op': 'CONFIG_EXPORT', 'files': result.get('count'), 'bytes': len(data)})
    return Response(data, mimetype='application/gzip', headers={'Content-Disposition': f'attachment; filename={name}',
                                                                'Cache-Control': 'no-store'})


@app.route('/export')
@require_login
def export():
    entries, version, problems = read_list()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(['ID', 'MAC', 'Tunnel-Type', 'Tunnel-Medium-Type', 'Tunnel-Private-Group-ID', 'Last-Modified'])
    for e in entries:
        writer.writerow([e['id'], e['mac'], e['tunnel_type'], e['tunnel_medium'], e['tunnel_group'], e['modified']])

    output.seek(0)  #  游標重設，確保 getvalue() 抓到完整內容
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=export.csv'}
    )


def parse_import_csv(text):
    """回傳 (rows, errors)。任何一列有問題就整批拒絕；訊息只列行號與檢核結果。"""
    rows = []
    errors = []
    seen_ids = {}
    seen_macs = {}
    reader = csv.reader(text.splitlines())
    next(reader, None)
    for line_no, row in enumerate(reader, start=2):
        if not any(cell.strip() for cell in row):
            continue
        if len(row) < 5:
            errors.append(f"第 {line_no} 行：欄位不足")
            continue
        entry_id, mac, tunnel_type, tunnel_medium, tunnel_group = [cell.strip() for cell in row[:5]]
        mac = normalize_mac(mac)
        if not is_valid_id(entry_id):
            errors.append(f"第 {line_no} 行：裝置名稱格式錯誤")
        elif entry_id.lower() in seen_ids:
            errors.append(f"第 {line_no} 行：裝置名稱與第 {seen_ids[entry_id.lower()]} 行重複")
        if not is_valid_mac(mac):
            errors.append(f"第 {line_no} 行：MAC 格式錯誤")
        elif mac in seen_macs:
            errors.append(f"第 {line_no} 行：MAC 與第 {seen_macs[mac]} 行重複")
        attr_errors = attrs_errors(tunnel_type, tunnel_medium, tunnel_group)
        errors += [f"第 {line_no} 行：{message}" for message in attr_errors]
        seen_ids.setdefault(entry_id.lower(), line_no)
        seen_macs.setdefault(mac, line_no)
        if not attr_errors:
            rows.append({'line': line_no, 'id': entry_id, 'mac': mac, 'tunnel_type': str(int(tunnel_type)),
                         'tunnel_medium': str(int(tunnel_medium)), 'tunnel_group': str(int(tunnel_group))})
    return rows, errors


def plan_import(rows, entries, mode):
    """先比 MAC，再比裝置名稱，找不到才算新增。mode=replace 時，檔案沒有的既有資料會刪除。"""
    matches = {}
    used = set()
    mac_index = {}
    for i, e in enumerate(entries):
        mac_index.setdefault(e['mac'], i)
    pending = []
    for row in rows:
        i = mac_index.get(row['mac'])
        if i is not None and i not in used:
            matches[row['line']] = i
            used.add(i)
        else:
            pending.append(row)
    errors = []
    added = []
    for row in pending:
        candidates = [i for i, e in enumerate(entries) if e['id'].lower() == row['id'].lower() and i not in used]
        if len(candidates) > 1:
            errors.append(f"第 {row['line']} 行：裝置名稱 {row['id']} 對應到多筆既有資料，請先處理重複")
        elif candidates:
            matches[row['line']] = candidates[0]
            used.add(candidates[0])
        else:
            added.append(row)
    if errors:
        return {'errors': errors}

    def clean(row, modified=''):
        return {'id': row['id'], 'mac': row['mac'], 'tunnel_type': row['tunnel_type'],
                'tunnel_medium': row['tunnel_medium'], 'tunnel_group': row['tunnel_group'], 'modified': modified}

    replacements = {}
    changed = []
    unchanged = 0
    for row in rows:
        if row['line'] not in matches:
            continue
        index = matches[row['line']]
        before = entries[index]
        after = clean(row, before['modified'])
        replacements[index] = after
        diff = entry_diff(before, after)
        if diff:
            changed.append({'before': before, 'after': after, 'changes': diff})
        else:
            unchanged += 1

    final = []
    deleted = []
    imported = set()
    for i, e in enumerate(entries):
        if i in replacements:
            final.append(replacements[i])
            imported.add(id(replacements[i]))
        elif mode == 'replace':
            deleted.append(e)
        else:
            final.append(e)
    new_entries = [clean(row) for row in added]
    imported.update(id(e) for e in new_entries)
    final += new_entries

    # 匯入後的整份名單再檢核一次：牽涉匯入資料的重複要擋，純既有的重複只提示
    warnings = []
    d = find_duplicates(final)
    for kind, label, key in (('ids', '裝置名稱', 'id'), ('macs', 'MAC', 'mac')):
        for group in d[kind]:
            if any(id(e) in imported for e in group):
                errors.append(f"{label} {group[0][key]} 匯入後會重複")
            else:
                warnings.append(f"{label} {group[0][key]} 目前已重複（{len(group)} 筆），這次匯入不會處理")
    return {'errors': errors, 'warnings': warnings, 'added': new_entries, 'changed': changed,
            'deleted': deleted, 'unchanged': unchanged, 'final': final}


def clean_pending():
    cutoff = time.time() - PENDING_MAX_AGE
    for name in os.listdir(PENDING_DIR):
        path = os.path.join(PENDING_DIR, name)
        if os.path.getmtime(path) < cutoff:
            os.unlink(path)


def pending_path(token):
    return os.path.join(PENDING_DIR, f"{token}.json")


def valid_token(token):
    return bool(re.fullmatch(r'[0-9a-f]{32}', token or ''))


@app.route('/import/preview', methods=['POST'])
@require_login
def import_preview():
    file = request.files.get('csvfile')
    if not file or not file.filename:
        flash('請選擇 CSV 檔案', 'error')
        return redirect('/')
    mode = 'replace' if request.form.get('mode') == 'replace' else 'merge'
    try:
        text = file.read().decode('utf-8-sig')
    except UnicodeDecodeError:
        return render_template('import_preview.html', errors=['CSV 必須是 UTF-8 編碼'], mode=mode), 400
    rows, errors = parse_import_csv(text)
    if not errors and not rows:
        errors = ['CSV 沒有資料']
    if errors:
        return render_template('import_preview.html', errors=errors, mode=mode), 400
    entries, version, problems = read_list()
    if problems:
        return render_template('import_preview.html', errors=['名單檔格式異常，請先查看放行裝置清單上方的資料檢核'], mode=mode), 400
    plan = plan_import(rows, entries, mode)
    if plan['errors']:
        return render_template('import_preview.html', errors=plan['errors'], mode=mode), 400
    has_changes = bool(plan['added'] or plan['changed'] or plan['deleted'])
    token = ''
    if has_changes:
        clean_pending()
        token = secrets.token_hex(16)
        fd = os.open(pending_path(token), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump({'rows': rows, 'mode': mode, 'version': version}, f)
        session['import_token'] = token
    return render_template('import_preview.html', errors=[], plan=plan, mode=mode, token=token,
                           has_changes=has_changes, labels=FIELD_LABELS)


@app.route('/import/commit', methods=['POST'])
@require_login
def import_commit():
    token = request.form.get('token', '')
    if request.form.get('confirmed') != '1' or not valid_token(token) or session.get('import_token') != token \
            or not os.path.exists(pending_path(token)):
        flash('匯入確認已失效，名單未變更，請重新上傳', 'error')
        return redirect('/')
    with open(pending_path(token), 'r', encoding='utf-8') as f:
        pending = json.load(f)
    os.unlink(pending_path(token))
    session.pop('import_token', None)
    with data_lock():
        entries, version, problems = read_list()
        if problems or version != pending['version']:
            flash('名單在確認期間已被變更，這次匯入已取消，請重新上傳', 'error')
            return redirect('/')
        plan = plan_import(pending['rows'], entries, pending['mode'])
        if plan['errors']:
            flash('匯入檢核未通過，名單未變更，請重新上傳', 'error')
            return redirect('/')
        stamp = now_text()
        for e in plan['added']:
            e['modified'] = stamp
        for c in plan['changed']:
            c['after']['modified'] = stamp
        touched = [e['mac'] for e in plan['added']] + [c['after']['mac'] for c in plan['changed']]
        removed = [e['mac'] for e in plan['deleted']] + \
                  [c['before']['mac'] for c in plan['changed'] if c['before']['mac'] != c['after']['mac']]
        records = [{'action': 'add', 'after': public_entry(e)} for e in plan['added']]
        records += [{'action': 'edit', 'before': public_entry(c['before']), 'after': public_entry(c['after']),
                     'changes': c['changes']} for c in plan['changed']]
        records += [{'action': 'delete', 'before': public_entry(e)} for e in plan['deleted']]
        summary = {'mode': pending['mode'], 'added': len(plan['added']), 'changed': len(plan['changed']),
                   'deleted': len(plan['deleted']), 'unchanged': plan['unchanged']}
        backup = commit('IMPORT', plan['final'], touched, removed, records, stamp, summary)
    logging.info(f"IMPORT - {summary} | User: {session.get('user')} | Backup: {backup}")
    flash(f"匯入完成：新增 {summary['added']} 筆、修改 {summary['changed']} 筆、刪除 {summary['deleted']} 筆", 'success')
    return redirect('/')


@app.route('/import/cancel', methods=['POST'])
@require_login
def import_cancel():
    token = request.form.get('token', '')
    if valid_token(token) and session.get('import_token') == token and os.path.exists(pending_path(token)):
        os.unlink(pending_path(token))
    session.pop('import_token', None)
    flash('已取消匯入，名單未變更', 'success')
    return redirect('/')


def load_aps():
    if not os.path.exists(AP_FILE):
        return []
    with open(AP_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def ap_version(aps):
    return hashlib.sha256(json.dumps(aps, sort_keys=True).encode()).hexdigest()


def save_aps(aps):
    fd, tmp = tempfile.mkstemp(dir=STATE_DIR)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(aps, f, indent=0, ensure_ascii=False)
        os.replace(tmp, AP_FILE)
    except Exception:
        os.unlink(tmp)
        raise


def backup_aps(op, aps):
    os.makedirs(AP_BACKUP_DIR, mode=0o700, exist_ok=True)
    name = f"{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}-{op}.json"
    with open(os.path.join(AP_BACKUP_DIR, name), 'w', encoding='utf-8') as f:
        json.dump(aps, f, indent=0, ensure_ascii=False)
    for old in sorted(os.listdir(AP_BACKUP_DIR))[:-BACKUP_KEEP]:
        os.unlink(os.path.join(AP_BACKUP_DIR, old))
    return name


def clean_ap_fields(name, ip, mac):
    """回傳 (row, errors)。IP 與 MAC 會轉成統一寫法，才能比對重複。"""
    errors = []
    name = name.strip()
    mac = normalize_mac(mac)
    if not AP_NAME_RE.fullmatch(name):
        errors.append('裝置名稱格式錯誤（英數字開頭，可用英數字與 _ . -，最多 64 字）')
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        errors.append('IP 格式錯誤')
    if not is_valid_mac(mac):
        errors.append('MAC 格式錯誤')
    return {'name': name, 'ip': ip, 'mac': mac, 'modified': ''}, errors


def ap_duplicate_errors(aps, wording):
    errors = []
    for label, key in (('裝置名稱', 'name'), ('IP', 'ip'), ('MAC', 'mac')):
        seen = set()
        for a in aps:
            value = a[key].lower()
            if value in seen:
                errors.append(f"{label} {a[key]} {wording}")
            seen.add(value)
    return errors


def parse_ap_csv(text):
    """第一行第二欄不是 IP 就視為標題。任何一列有問題就整批拒絕。"""
    rows = []
    errors = []
    lines = text.splitlines()
    delimiter = '\t' if lines and '\t' in lines[0] else ','
    seen = {'name': {}, 'ip': {}, 'mac': {}}
    labels = {'name': '裝置名稱', 'ip': 'IP', 'mac': 'MAC'}
    first = True
    for line_no, row in enumerate(csv.reader(lines, delimiter=delimiter), start=1):
        if not any(cell.strip() for cell in row):
            continue
        if first:
            first = False
            try:
                ipaddress.ip_address(row[1].strip() if len(row) > 1 else '')
            except ValueError:
                continue
        if len(row) < 3:
            errors.append(f"第 {line_no} 行：欄位不足（需要裝置名稱、IP、MAC）")
            continue
        parsed, row_errors = clean_ap_fields(row[0], row[1], row[2])
        errors += [f"第 {line_no} 行：{message}" for message in row_errors]
        if row_errors:
            continue
        for key, label in labels.items():
            value = parsed[key].lower()
            if value in seen[key]:
                errors.append(f"第 {line_no} 行：{label}與第 {seen[key][value]} 行重複")
            seen[key].setdefault(value, line_no)
        rows.append(parsed)
    return rows, errors


def plan_ap_import(rows, aps, mode):
    """依序用 MAC、裝置名稱、IP 找既有資料，都找不到才算新增。mode=replace 時檔案沒有的會刪除。"""
    replacements = {}
    added = []
    for row in rows:
        for key in ('mac', 'name', 'ip'):
            index = next((i for i, a in enumerate(aps) if i not in replacements and a[key].lower() == row[key].lower()), None)
            if index is not None:
                replacements[index] = row
                break
        else:
            added.append(row)
    changed = []
    unchanged = 0
    final = []
    deleted = []
    for i, a in enumerate(aps):
        row = replacements.get(i)
        if row is None:
            if mode == 'replace':
                deleted.append(a)
            else:
                final.append(a)
        elif all(row[k] == a[k] for k in AP_FIELD_LABELS):
            final.append(a)
            unchanged += 1
        else:
            final.append(row)
            changed.append({'before': a, 'after': row, 'changes': {k: [a[k], row[k]] for k in AP_FIELD_LABELS if a[k] != row[k]}})
    final += added
    return {'errors': ap_duplicate_errors(final, '匯入後會重複'), 'added': added, 'changed': changed,
            'deleted': deleted, 'unchanged': unchanged, 'final': final}


def ap_index():
    aps = load_aps()
    return {a['mac']: a['name'] for a in aps}, {a['ip']: a['name'] for a in aps}


def ap_name_for(called, ip, nas_ip, index):
    """先比 Called-Station-Id 的 MAC。多數 AP 送的是 BSSID，與清單的 MAC 不同，比不到就比送認證的 IP。"""
    by_mac, by_ip = index
    name = by_mac.get(split_called(called)[0]) or by_ip.get(ip) or by_ip.get(nas_ip)
    return name or ('不在清單' if called else '未記錄')


def ap_preview_page(op, plan, aps, mode=''):
    if plan['errors']:
        return render_template('ap_preview.html', errors=plan['errors'], mode=mode), 400
    token = ''
    has_changes = bool(plan['added'] or plan['changed'] or plan['deleted'])
    if has_changes:
        clean_pending()
        token = secrets.token_hex(16)
        fd = os.open(pending_path(token), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump({'op': op, 'version': ap_version(aps), 'mode': mode, **plan}, f)
        session['ap_token'] = token
    return render_template('ap_preview.html', errors=[], plan=plan, mode=mode, token=token,
                           has_changes=has_changes, labels=AP_FIELD_LABELS)


@app.route('/ap')
@require_login
def ap_list():
    aps = sorted(load_aps(), key=lambda a: ipaddress.ip_address(a['ip']).packed)
    return render_template('ap.html', aps=aps, defaults=default_attrs())


@app.route('/ap/export')
@require_login
def ap_export():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['裝置名稱', 'IP', 'MAC'])
    for a in sorted(load_aps(), key=lambda a: ipaddress.ip_address(a['ip']).packed):
        writer.writerow([a['name'], a['ip'], a['mac']])
    # BOM 讓 Excel 正確顯示中文標題
    return Response('﻿' + output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=ap-list.csv'})


@app.route('/ap/preview', methods=['POST'])
@require_login
def ap_preview():
    aps = load_aps()
    if request.form.get('op') == 'delete':
        mac = normalize_mac(request.form.get('key', ''))
        target = [a for a in aps if a['mac'] == mac]
        if not target:
            flash('找不到這台 AP，清單可能已被變更', 'error')
            return redirect('/ap')
        plan = {'errors': [], 'added': [], 'changed': [], 'deleted': target, 'unchanged': 0,
                'final': [a for a in aps if a['mac'] != mac]}
        return ap_preview_page('AP_DELETE', plan, aps)
    row, errors = clean_ap_fields(request.form.get('name', ''), request.form.get('ip', ''), request.form.get('mac', ''))
    final = aps + [row]
    if errors:
        plan = {'errors': errors}
    else:
        plan = {'errors': ap_duplicate_errors(final, '已存在'), 'added': [row], 'changed': [], 'deleted': [],
                'unchanged': 0, 'final': final}
    return ap_preview_page('AP_ADD', plan, aps)


@app.route('/ap/import/preview', methods=['POST'])
@require_login
def ap_import_preview():
    file = request.files.get('csvfile')
    if not file or not file.filename:
        flash('請選擇 CSV 檔案', 'error')
        return redirect('/ap')
    mode = 'replace' if request.form.get('mode') == 'replace' else 'merge'
    raw = file.read()
    # Excel 在繁體中文 Windows 另存 CSV 預設是 Big5
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        try:
            text = raw.decode('cp950')
        except UnicodeDecodeError:
            return render_template('ap_preview.html', errors=['CSV 必須是 UTF-8 或 Big5 編碼'], mode=mode), 400
    rows, errors = parse_ap_csv(text)
    if not errors and not rows:
        errors = ['CSV 沒有資料']
    if errors:
        return render_template('ap_preview.html', errors=errors, mode=mode), 400
    aps = load_aps()
    return ap_preview_page('AP_IMPORT', plan_ap_import(rows, aps, mode), aps, mode)


@app.route('/ap/commit', methods=['POST'])
@require_login
def ap_commit():
    token = request.form.get('token', '')
    if request.form.get('confirmed') != '1' or not valid_token(token) or session.get('ap_token') != token \
            or not os.path.exists(pending_path(token)):
        flash('確認已失效，AP 清單未變更，請重新操作', 'error')
        return redirect('/ap')
    with open(pending_path(token), 'r', encoding='utf-8') as f:
        pending = json.load(f)
    os.unlink(pending_path(token))
    session.pop('ap_token', None)
    with data_lock():
        aps = load_aps()
        if ap_version(aps) != pending['version']:
            flash('AP 清單在確認期間已被變更，這次操作已取消，請重新操作', 'error')
            return redirect('/ap')
        stamp = now_text()
        for a in pending['final']:
            a['modified'] = a['modified'] or stamp
        op = pending['op']
        backup = backup_aps(op, aps)
        save_aps(pending['final'])
        summary = {'added': len(pending['added']), 'changed': len(pending['changed']), 'deleted': len(pending['deleted'])}
        log_change({'op': op + '_SUMMARY', 'backup': backup, 'mode': pending['mode'], **summary})
        for a in pending['added']:
            log_change({'op': op, 'backup': backup, 'action': 'add', 'after': {k: a[k] for k in AP_FIELD_LABELS}})
        for c in pending['changed']:
            log_change({'op': op, 'backup': backup, 'action': 'edit', 'before': {k: c['before'][k] for k in AP_FIELD_LABELS},
                        'after': {k: c['after'][k] for k in AP_FIELD_LABELS}, 'changes': c['changes']})
        for a in pending['deleted']:
            log_change({'op': op, 'backup': backup, 'action': 'delete', 'before': {k: a[k] for k in AP_FIELD_LABELS}})
    logging.info(f"{op} - {summary} | User: {session.get('user')} | Backup: {backup}")
    flash(f"AP 清單已更新：新增 {summary['added']} 筆、修改 {summary['changed']} 筆、刪除 {summary['deleted']} 筆", 'success')
    return redirect('/ap')


@app.route('/ap/cancel', methods=['POST'])
@require_login
def ap_cancel():
    token = request.form.get('token', '')
    if valid_token(token) and session.get('ap_token') == token and os.path.exists(pending_path(token)):
        os.unlink(pending_path(token))
    session.pop('ap_token', None)
    flash('已取消，AP 清單未變更', 'success')
    return redirect('/ap')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        address = request.remote_addr
        if login_locked(address):
            logging.warning(f'login locked: {address}')
            return render_template('login.html', error=f'失敗次數過多，請 {LOGIN_LOCK_SECONDS // 60} 分鐘後再試'), 429
        env = load_env()
        password_ok = check_password_hash(env['ADMIN_PASSWORD_HASH'], request.form.get('password', ''))
        if password_ok and hmac.compare_digest(request.form.get('username', '').encode(), env['ADMIN_USERNAME'].encode()):
            login_clear(address)
            session.clear()
            session['user'] = env['ADMIN_USERNAME']
            session['cred'] = credential_tag(env)
            return redirect('/setup' if not load_settings().get('setup_done') else '/')
        login_failed(address)
        logging.warning(f'login failed: {address}')
        return render_template('login.html', error='帳號或密碼錯誤')
    return render_template('login.html')


def account_page(env, status=200, **values):
    values.setdefault('allowed_cidrs', '\n'.join(load_settings().get('allowed_cidrs', [])))
    return render_template('account.html', username=env['ADMIN_USERNAME'], min_length=MIN_PASSWORD_LENGTH,
                           client_ip=request.remote_addr, **values), status


@app.route('/account/allowed-ips', methods=['POST'])
@require_login
def account_allowed_ips():
    env = load_env()
    text = request.form.get('allowed_cidrs', '')
    if not check_password_hash(env['ADMIN_PASSWORD_HASH'], request.form.get('current_password', '')):
        return account_page(env, 400, ip_error='目前密碼錯誤，來源 IP 限制未變更', allowed_cidrs=text)
    cidrs, error = parse_cidrs(text)
    if not error and not source_allowed(request.remote_addr, cidrs):
        error = f'目前連線的 IP {request.remote_addr} 不在清單內，儲存後會無法再連線，請先把它加入'
    if error:
        return account_page(env, 400, ip_error=error, allowed_cidrs=text)
    current = load_settings()
    before = current.get('allowed_cidrs', [])
    if cidrs == before:
        return account_page(env, ip_message='來源 IP 限制沒有變更')
    save_settings({**current, 'allowed_cidrs': cidrs})
    log_change({'op': 'ALLOWED_IPS', 'before': before, 'after': cidrs})
    logging.info(f"ALLOWED_IPS - {before} -> {cidrs} | User: {session.get('user')}")
    return account_page(env, ip_message='來源 IP 限制已更新，立即生效')


@app.route('/account', methods=['GET', 'POST'])
@require_login
def account():
    env = load_env()
    if request.method == 'GET':
        return account_page(env)
    new_username = request.form['username'].strip()
    new_password = request.form['new_password']
    error = None
    if not check_password_hash(env['ADMIN_PASSWORD_HASH'], request.form['current_password']):
        error = '目前密碼錯誤'
    elif not USERNAME_RE.fullmatch(new_username):
        error = '帳號只能使用英數字與 _ . -（3 到 32 字）'
    elif new_password != request.form['confirm_password']:
        error = '兩次輸入的新密碼不一致'
    elif new_password and password_problem(new_password, new_username):
        error = password_problem(new_password, new_username)
    elif new_password and check_password_hash(env['ADMIN_PASSWORD_HASH'], new_password):
        error = '新密碼不可與目前密碼相同'
    if error:
        return account_page(env, 400, error=error)
    # 新密碼留白表示只改帳號
    password_hash = generate_password_hash(new_password) if new_password else env['ADMIN_PASSWORD_HASH']
    old_username = env['ADMIN_USERNAME']
    save_credentials(new_username, password_hash)
    logging.info(f"ACCOUNT - credentials changed | User: {new_username} | Password changed: {bool(new_password)}")
    log_change({'op': 'ACCOUNT', 'username': [old_username, new_username], 'password_changed': bool(new_password)})
    env = load_env()
    session.clear()
    session['user'] = env['ADMIN_USERNAME']
    session['cred'] = credential_tag(env)
    return account_page(env, message='帳號設定已更新')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')



# ---- 登入失敗限制 ----
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_SECONDS = 300
_login_failures = {}
_login_lock = threading.Lock()


def login_locked(address):
    with _login_lock:
        count, last = _login_failures.get(address, (0, 0))
        return count >= LOGIN_MAX_FAILURES and time.time() - last < LOGIN_LOCK_SECONDS


def login_failed(address):
    with _login_lock:
        now = time.time()
        count, last = _login_failures.get(address, (0, 0))
        _login_failures[address] = (1 if now - last >= LOGIN_LOCK_SECONDS else count + 1, now)
        if len(_login_failures) > 10000:
            _login_failures.clear()


def login_clear(address):
    with _login_lock:
        _login_failures.pop(address, None)


def password_problem(password, username=''):
    """回傳問題說明，沒問題回傳空字串。"""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f'密碼至少要 {MIN_PASSWORD_LENGTH} 個字元'
    classes = sum(bool(re.search(pattern, password)) for pattern in (r'[a-z]', r'[A-Z]', r'[0-9]', r'[^A-Za-z0-9]'))
    if classes < 3:
        return '密碼要包含大寫、小寫、數字、符號其中至少三種'
    if username and username.lower() in password.lower():
        return '密碼不可包含帳號'
    return ''


# ---- 與 root helper 溝通 ----
HELPER_TIMEOUT = 150
REQUEST_DIR = os.path.join(STATE_DIR, 'requests')
RESULT_DIR = os.path.join(STATE_DIR, 'results')


def helper_call(action, timeout=HELPER_TIMEOUT, **params):
    """把請求放到佇列，由 systemd 啟動 root helper 處理，再等結果。請求可能含密碼，helper 讀取後立刻刪除。"""
    request_id = secrets.token_hex(16)
    fd, tmp = tempfile.mkstemp(dir=REQUEST_DIR, prefix='.tmp-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump({'action': action, 'params': params}, f)
        os.replace(tmp, os.path.join(REQUEST_DIR, f'{request_id}.json'))
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    path = os.path.join(RESULT_DIR, f'{request_id}.json')
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.3)
        try:
            with open(path, encoding='utf-8') as f:
                return json.load(f)
        except (OSError, ValueError):
            continue
    return {'ok': False, 'error': '系統沒有在時間內回應，請查看 journalctl -u radius-manager-helper'}


def update_settings(**values):
    with data_lock():
        save_settings({**load_settings(), **values})


def uploaded_text(name):
    item = request.files.get(name)
    if not item or not item.filename:
        return ''
    try:
        return item.read(1024 * 1024).decode('utf-8')
    except UnicodeDecodeError:
        return ''


def random_secret():
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(8))


def parse_client_networks(text):
    """空白分隔的網段。0.0.0.0 代表不限來源，存成 0.0.0.0/0。"""
    items = [item for item in re.split(r'[\s,，]+', text.strip()) if item]
    if not items:
        return [], '請至少填寫一個網段'
    networks = []
    for item in items:
        try:
            network = str(ipaddress.ip_network('0.0.0.0/0' if item == '0.0.0.0' else item, strict=False))
        except ValueError:
            return [], f'不是正確的 IP 或網段：{item}'
        if network not in networks:
            networks.append(network)
    return networks, None


def apply_radius_clients(form):
    secret = form.get('radius_secret', '').strip()
    networks, error = parse_client_networks(form.get('radius_networks', ''))
    if error:
        return error
    if not re.fullmatch(r'[A-Za-z0-9._~-]{8,64}', secret):
        return 'RADIUS secret 要 8 到 64 個字元，只能用英數字與 . _ ~ -'
    result = helper_call('radius_clients', secret=secret, networks=networks)
    if not result.get('ok'):
        return result.get('error', '套用失敗')
    update_settings(radius_secret=secret, radius_networks=networks)
    log_change({'op': 'RADIUS_CLIENTS', 'networks': networks})
    return None


def ad_params(form):
    return {'realm': form.get('realm', ''), 'workgroup': form.get('workgroup', ''), 'dc': form.get('dc', ''), 'computer': form.get('computer', ''),
            'admin_user': form.get('admin_user', ''), 'admin_password': form.get('admin_password', ''),
            'test_user': form.get('test_user', ''), 'test_password': form.get('test_password', '')}


def apply_ad(form):
    result = helper_call('ad_join', **ad_params(form))
    if result.get('ok'):
        update_settings(ad_enabled=True, ad_realm=form.get('realm', '').strip().upper(), ad_workgroup=form.get('workgroup', '').strip().upper(),
                        ad_dc=form.get('dc', '').strip(), ad_computer=form.get('computer', '').strip().upper())
        log_change({'op': 'AD_ENABLE', 'realm': form.get('realm', '').strip().upper()})
    return result


def google_form_values(form):
    domain = form.get('google_domain', '').strip().lower()
    return domain, ','.join(f'dc={part}' for part in domain.split('.')) if domain else ''


def apply_google(form):
    domain, base_dn = google_form_values(form)
    result = helper_call('google_configure', identity=form.get('identity', ''), password=form.get('access_password', ''), base_dn=base_dn,
                         cert_pem=uploaded_text('cert_file'), key_pem=uploaded_text('key_file'),
                         test_email=form.get('test_email', ''), test_password=form.get('test_password', ''))
    if result.get('ok'):
        update_settings(google_enabled=True, google_domain=domain)
        log_change({'op': 'GOOGLE_ENABLE', 'domain': domain})
    return result


def apply_eap_cert(form):
    if form.get('cert_mode') == 'upload':
        return helper_call('eap_cert', mode='upload', cert_pem=uploaded_text('cert_file'), key_pem=uploaded_text('key_file'))
    return helper_call('eap_cert', mode='self_signed', name=form.get('cert_name', ''))


def setup_cert_extra(current):
    info = helper_call('eap_cert_info', timeout=30)
    details = info.get('details') or {}
    return {'cert_details': details, 'cert_name': details.get('subject') or (current.get('org_name', '') + 'woofradius')}


# ---- 初始化精靈 ----
SETUP_STEPS = (('org', '單位資料'), ('admin', '管理者帳號'), ('access', '來源 IP'), ('radius', 'RADIUS 用戶端'),
               ('ad', 'AD 帳號驗證'), ('google', 'Google 帳號驗證'), ('cert', '伺服器憑證'), ('ssid', 'SSID 規則'), ('finish', '完成'))
SETUP_ORDER = [key for key, _ in SETUP_STEPS]
COMMON_TIMEZONES = ('Asia/Taipei', 'Asia/Hong_Kong', 'Asia/Shanghai', 'Asia/Tokyo', 'Asia/Singapore', 'UTC')


def setup_authorized():
    """建立管理者之前靠一次性連結；建立之後就是一般登入。"""
    env = load_env()
    if env.get('ADMIN_PASSWORD_HASH'):
        return 'user' in session and session.get('cred') == credential_tag(env)
    stored = env.get('SETUP_TOKEN_HASH', '')
    return bool(stored) and session.get('setup_token') == stored


def setup_ssid_default():
    """依剛剛啟用的驗證方式預填，管理者可以再改。"""
    current = load_settings()
    ad, google = current.get('ad_enabled'), current.get('google_enabled')
    rows = [{'keyword': 'Device', 'auth': 'mac', 'vlan': ''}]
    if ad:
        rows.append({'keyword': 'Staff', 'auth': 'ad', 'vlan': ''})
    if google:
        rows.append({'keyword': 'Google', 'auth': 'google', 'vlan': ''})
    return {'rules': rows, 'default': {'auth': 'ad' if ad else 'google' if google else 'reject', 'vlan': ''}}


def setup_render(step, status=200, **values):
    current = load_settings()
    index = SETUP_ORDER.index(step)
    return render_template('setup.html', step=step, steps=SETUP_STEPS, index=index, previous=SETUP_ORDER[index - 1] if index else '',
                           settings=current, client_ip=request.remote_addr, timezones=COMMON_TIMEZONES,
                           auth_labels={k: v for k, v in SSID_AUTH_LABELS.items() if k != 'proxy'}, min_length=MIN_PASSWORD_LENGTH, **values), status


@app.route('/setup', methods=['GET'])
def setup_start():
    current = load_settings()
    if current.get('setup_done'):
        return redirect('/')
    env = load_env()
    token = request.args.get('token', '')
    if token and env.get('SETUP_TOKEN_HASH') and hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), env['SETUP_TOKEN_HASH']):
        session['setup_token'] = env['SETUP_TOKEN_HASH']
        return redirect('/setup')
    if not setup_authorized():
        if env.get('ADMIN_PASSWORD_HASH'):
            return redirect('/login')
        return Response('請使用安裝完成時顯示的一次性連結開始設定。\n連結遺失時，在主機上執行：sudo radius-manager setup-url\n',
                        status=403, mimetype='text/plain; charset=utf-8')
    return redirect(f"/setup/{current.get('setup_step', 'org')}")


def setup_advance(step):
    next_step = SETUP_ORDER[SETUP_ORDER.index(step) + 1]
    update_settings(setup_step=next_step)
    return redirect(f'/setup/{next_step}')


@app.route('/setup/<step>', methods=['GET', 'POST'])
def setup_page(step):
    if load_settings().get('setup_done'):
        return redirect('/')
    if step not in SETUP_ORDER:
        return redirect('/setup')
    if not setup_authorized():
        return redirect('/setup')
    current = load_settings()
    reached = current.get('setup_step', 'org')
    # 不能跳過還沒走到的步驟，例如還沒建立管理者
    if SETUP_ORDER.index(step) > SETUP_ORDER.index(reached):
        return redirect(f'/setup/{reached}')
    if request.method == 'GET':
        extra = {}
        if step == 'radius':
            extra = {'secret': current.get('radius_secret') or random_secret(), 'networks': '\n'.join(current.get('radius_networks', [])) or '0.0.0.0'}
        if step == 'access':
            extra = {'cidrs': '\n'.join(current.get('allowed_cidrs', [])) or request.remote_addr}
        if step == 'ssid':
            extra = {'rules': setup_ssid_default() if not os.path.exists(SSID_RULES_FILE) else load_ssid_rules(), 'default_vlan': current.get('default_vlan', DEFAULT_VLAN)}
        if step == 'cert':
            extra = setup_cert_extra(current)
        return setup_render(step, **extra)
    form = request.form
    action = form.get('action', 'save')
    if step == 'org':
        name = form.get('org_name', '').strip()
        timezone = form.get('timezone', '').strip()
        if not name or len(name) > 60 or not name.isprintable():
            return setup_render(step, 400, error='請填寫單位名稱（60 字以內）')
        result = helper_call('timezone', timezone=timezone, timeout=30)
        if not result.get('ok'):
            return setup_render(step, 400, error=result.get('error'))
        update_settings(org_name=name, timezone=timezone)
        # 安裝時自動產生的 RADIUS 憑證改用「單位名稱 + woofradius」，裝置信任時不會看到無意義的名稱
        result = helper_call('eap_cert_initial', org_name=name, timeout=60)
        if not result.get('ok'):
            flash(f"RADIUS 憑證沒有改名：{result.get('error', '')}，可在「RADIUS 伺服器憑證」步驟重新產生", 'error')
        return setup_advance(step)
    if step == 'admin':
        username = form.get('username', '').strip()
        password = form.get('password', '')
        error = None
        if not USERNAME_RE.fullmatch(username):
            error = '帳號只能使用英數字與 _ . -（3 到 32 字）'
        elif password != form.get('confirm_password', ''):
            error = '兩次輸入的密碼不一致'
        else:
            error = password_problem(password, username)
        if error:
            return setup_render(step, 400, error=error, username=username)
        save_credentials(username, generate_password_hash(password))
        env = load_env()
        session.clear()
        session['user'] = env['ADMIN_USERNAME']
        session['cred'] = credential_tag(env)
        log_change({'op': 'SETUP_ADMIN', 'username': username})
        return setup_advance(step)
    if step == 'access':
        cidrs, error = parse_cidrs(form.get('allowed_cidrs', ''))
        if not error and not source_allowed(request.remote_addr, cidrs):
            error = f'目前連線的 IP {request.remote_addr} 不在清單內，儲存後會無法再連線，請先把它加入'
        if error:
            return setup_render(step, 400, error=error, cidrs=form.get('allowed_cidrs', ''))
        update_settings(allowed_cidrs=cidrs)
        log_change({'op': 'ALLOWED_IPS', 'after': cidrs})
        return setup_advance(step)
    if step == 'radius':
        error = apply_radius_clients(form)
        if error:
            return setup_render(step, 400, error=error, secret=form.get('radius_secret', ''), networks=form.get('radius_networks', ''))
        return setup_advance(step)
    if step == 'ad':
        if action == 'skip':
            return setup_advance(step)
        result = apply_ad(form)
        if result.get('ok'):
            return setup_render(step, result=result, verified=True, form=form)
        return setup_render(step, 400, result=result, form=form)
    if step == 'google':
        if action == 'skip':
            return setup_advance(step)
        result = apply_google(form)
        if result.get('ok'):
            return setup_render(step, result=result, verified=True, form=form)
        return setup_render(step, 400, result=result, form=form)
    if step == 'cert':
        if action == 'skip':
            return setup_advance(step)
        result = apply_eap_cert(form)
        if not result.get('ok'):
            return setup_render(step, 400, error=result.get('error'), **{**setup_cert_extra(load_settings()), 'cert_name': form.get('cert_name', '')})
        if form.get('cert_mode') != 'upload':
            update_settings(radius_fqdn=form.get('cert_name', '').strip())
        return setup_advance(step)
    if step == 'ssid':
        rules = []
        for keyword, auth, vlan in zip(form.getlist('keyword'), form.getlist('auth'), form.getlist('vlan')):
            if keyword.strip():
                rules.append({'keyword': keyword.strip(), 'auth': auth, 'vlan': vlan.strip()})
        default = {'auth': form.get('default_auth', ''), 'vlan': form.get('default_vlan_rule', '').strip()}
        default_vlan = form.get('default_vlan', '').strip()
        error = validate_ssid_rules(rules, default)
        if not error and not is_valid_number(default_vlan, 1, 4094):
            error = '名單裝置的預設 VLAN 必須是 1 到 4094'
        if error:
            return setup_render(step, 400, error=error, rules={'rules': rules, 'default': default}, default_vlan=default_vlan)
        save_radius_json(SSID_RULES_FILE, {'rules': rules, 'default': default})
        update_settings(default_vlan=default_vlan)
        log_change({'op': 'SSID_RULES', 'after': {'rules': rules, 'default': default}})
        return setup_advance(step)
    if step == 'finish':
        update_settings(setup_done=True)
        log_change({'op': 'SETUP_DONE'})
        flash('初始化完成。剛才的設定都可以在「系統設定」變更，也可以在那裡重新驗證 AD 與 Google。', 'success')
        return redirect('/settings/system')
    return redirect('/setup')


# ---- 系統設定：單位、RADIUS 用戶端、AD、Google、憑證 ----
def system_render(status=200, **values):
    current = load_settings()
    return render_template('system.html', settings=current, client_ip=request.remote_addr, version=app_version(),
                           secret=values.pop('secret', current.get('radius_secret', '')),
                           networks=values.pop('networks', '\n'.join(current.get('radius_networks', []))),
                           cert_details=helper_call('eap_cert_info', timeout=30).get('details'), **values), status


@app.route('/settings/system', methods=['GET', 'POST'])
@require_login
def system_settings():
    if request.method == 'GET':
        return system_render()
    form = request.form
    action = form.get('action', '')
    if action == 'org':
        name = form.get('org_name', '').strip()
        if not name or len(name) > 60 or not name.isprintable():
            return system_render(400, org_error='請填寫單位名稱（60 字以內）')
        update_settings(org_name=name)
        log_change({'op': 'ORG_NAME', 'after': name})
        return system_render(org_message='單位名稱已更新')
    if action == 'radius':
        error = apply_radius_clients(form)
        if error:
            return system_render(400, radius_error=error, secret=form.get('radius_secret', ''), networks=form.get('radius_networks', ''))
        return system_render(radius_message='RADIUS 用戶端已更新，FreeRADIUS 已重新啟動')
    if action == 'ad_join':
        result = apply_ad(form)
        return system_render(200 if result.get('ok') else 400, ad_result=result)
    if action == 'ad_test':
        return system_render(ad_result=helper_call('ad_test', test_user=form.get('test_user', ''), test_password=form.get('test_password', '')))
    if action == 'ad_disable':
        result = helper_call('ad_disable')
        if result.get('ok'):
            update_settings(ad_enabled=False)
            log_change({'op': 'AD_DISABLE'})
        return system_render(ad_result=result)
    if action == 'google_configure':
        result = apply_google(form)
        return system_render(200 if result.get('ok') else 400, google_result=result)
    if action == 'google_test':
        return system_render(google_result=helper_call('google_test', test_email=form.get('test_email', ''), test_password=form.get('test_password', '')))
    if action == 'google_disable':
        result = helper_call('google_disable')
        if result.get('ok'):
            update_settings(google_enabled=False)
            log_change({'op': 'GOOGLE_DISABLE'})
        return system_render(google_result=result)
    if action == 'eap_cert':
        result = apply_eap_cert(form)
        if result.get('ok'):
            if form.get('cert_mode') != 'upload':
                update_settings(radius_fqdn=form.get('cert_name', '').strip())
            log_change({'op': 'EAP_CERT', 'mode': form.get('cert_mode', ''), 'after': (result.get('details') or {}).get('subject', '')})
        return system_render(200 if result.get('ok') else 400, cert_result=result)
    if action == 'web_cert':
        result = helper_call('web_cert', cert_pem=uploaded_text('cert_file'), key_pem=uploaded_text('key_file'))
        return system_render(200 if result.get('ok') else 400, web_cert_result=result)
    return redirect('/settings/system')

TLS_HANDSHAKE_TIMEOUT = 10
TLS_IDLE_TIMEOUT = 120


class TLSThreadedServer(ThreadedWSGIServer):
    """Werkzeug 的 ssl_context 會包住監聽 socket，交握發生在主執行緒的 accept 裡：
    只要有一條連線連上後不交握（瀏覽器預先連線、掃描器），整個網站都會卡住。這裡改在每條連線的執行緒交握並設逾時。"""

    def __init__(self, host, port, wsgi_app, cert, key):
        super().__init__(host, port, wsgi_app)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        self.tls_context = context
        # WSGI 環境的 url_scheme 看這個值
        self.ssl_context = context

    def finish_request(self, request, client_address):
        request.settimeout(TLS_HANDSHAKE_TIMEOUT)
        try:
            connection = self.tls_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            connection.settimeout(TLS_IDLE_TIMEOUT)
            self.RequestHandlerClass(connection, client_address, self)
        except (ssl.SSLError, OSError):
            pass
        finally:
            connection.close()


if __name__ == '__main__':
    # 需要除錯時，在 env 檔加上 FLASK_DEBUG=1 並重啟服務；用完務必改回 0
    debug = load_env().get('FLASK_DEBUG') == '1'
    # debug 模式的 reloader 會多一個父程序，背景匯入只在實際服務的程序執行
    if not debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        threading.Thread(target=ingest_loop, daemon=True).start()
    host = os.environ.get('FLASK_RADIUS_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_RADIUS_PORT', '3333'))
    if debug or not os.path.exists(TLS_CERT):
        app.run(port=port, host=host, debug=debug, ssl_context=(TLS_CERT, TLS_KEY) if os.path.exists(TLS_CERT) else None, threaded=True)
    else:
        TLSThreadedServer(host, port, app, TLS_CERT, TLS_KEY).serve_forever()
