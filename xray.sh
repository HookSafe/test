#!/usr/bin/env bash
# ==============================================================================
#  Xray VLESS + TCP + TLS + XTLS Vision  一键部署/管理  v2.0
#  443=Xray | 80=留空给 acme standalone | 127.0.0.1:WEB_PORT=nginx(h2c) 伪装站
#  nginx 由本脚本安装并以「独立实例」运行，不占用 80，不动发行版站点配置
# ==============================================================================
set -euo pipefail
SCRIPT_VER="2.0.0"

ETC="/usr/local/etc/xray"
CONF="$ETC/config.json"
STATE="$ETC/manager.conf"
CERTS="$ETC/cert"
NGCONF="$ETC/fallback-nginx.conf"
BIN="/usr/local/bin/xray"
SHARE="/usr/local/share/xray"
SVC="xray.service"
FBSVC="xray-fallback.service"
UNIT="/etc/systemd/system/$SVC"
FBUNIT="/etc/systemd/system/$FBSVC"

if [ -t 1 ]; then R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[36m'; N=$'\033[0m'
else R=""; G=""; Y=""; B=""; N=""; fi
info(){ printf '%s\n' "${B}[i]${N} $*"; }
ok(){   printf '%s\n' "${G}[✓]${N} $*"; }
warn(){ printf '%s\n' "${Y}[!]${N} $*" >&2; }
err(){  printf '%s\n' "${R}[x]${N} $*" >&2; }
die(){  err "$*"; exit 1; }
need_root(){ [ "$(id -u)" = 0 ] || die "请用 root 运行"; }
need_systemd(){ { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; } || die "需要 systemd"; }

# ------------------------------- 状态 -----------------------------------------
defaults(){
  PORT="${PORT:-443}"; UUID="${UUID:-}"; EXTRA_UUIDS="${EXTRA_UUIDS:-}"
  FLOW="${FLOW:-xtls-rprx-vision}"
  DEST_MODE="${DEST_MODE:-local}"
  WEB_PORT="${WEB_PORT:-${LOCAL_PORT:-8080}}"      # 兼容 v1.x 的 LOCAL_PORT
  REMOTE_DEST="${REMOTE_DEST:-www.microsoft.com:80}"
  WEB_ROOT="${WEB_ROOT:-/var/www/xray-site}"
  ALPN="${ALPN:-h2,http/1.1}"; MIN_TLS="${MIN_TLS:-1.3}"
  LOG_LEVEL="${LOG_LEVEL:-warning}"; SERVER_IP="${SERVER_IP:-}"
  REMARK="${REMARK:-HK-Vision}"; CLIENT_FP="${CLIENT_FP:-chrome}"
  BLOCK_BT="${BLOCK_BT:-true}"; BLOCK_ADS="${BLOCK_ADS:-false}"; SNIFF="${SNIFF:-true}"
  XVER="${XVER:-0}"
  ACME_HOME="${ACME_HOME:-${HOME:-/root}/.acme.sh}"
}
load(){ if [ -f "$STATE" ]; then . "$STATE"; fi; defaults; }
save(){
  mkdir -p "$ETC"
  cat > "$STATE" <<EOF
PORT='$PORT'
UUID='$UUID'
EXTRA_UUIDS='$EXTRA_UUIDS'
FLOW='$FLOW'
DEST_MODE='$DEST_MODE'
WEB_PORT='$WEB_PORT'
REMOTE_DEST='$REMOTE_DEST'
WEB_ROOT='$WEB_ROOT'
ALPN='$ALPN'
MIN_TLS='$MIN_TLS'
LOG_LEVEL='$LOG_LEVEL'
SERVER_IP='$SERVER_IP'
REMARK='$REMARK'
CLIENT_FP='$CLIENT_FP'
BLOCK_BT='$BLOCK_BT'
BLOCK_ADS='$BLOCK_ADS'
SNIFF='$SNIFF'
XVER='$XVER'
ACME_HOME='$ACME_HOME'
EOF
  chmod 600 "$STATE"
}
dest_now(){ if [ "$DEST_MODE" = remote ]; then printf '%s' "$REMOTE_DEST"; else printf '127.0.0.1:%s' "$WEB_PORT"; fi; }
https_url(){ if [ "$PORT" = 443 ]; then printf 'https://%s/' "$SERVER_IP"; else printf 'https://%s:%s/' "$SERVER_IP" "$PORT"; fi; }

# ------------------------------- 工具 -----------------------------------------
is_uuid(){ [[ "${1:-}" =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; }
gen_uuid(){
  if [ -x "$BIN" ]; then "$BIN" uuid
  elif [ -r /proc/sys/kernel/random/uuid ]; then cat /proc/sys/kernel/random/uuid
  else python3 -c 'import uuid;print(uuid.uuid4())' 2>/dev/null || openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'; fi
}
detect_ip(){
  local u ip
  for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
    ip=$(curl -4 -fsS --max-time 8 "$u" 2>/dev/null | tr -d '[:space:]') || ip=""
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then printf '%s' "$ip"; return 0; fi
  done
  ip -4 -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p'
}
urlencode(){ local LC_ALL=C s="${1:-}" o="" c i; for ((i=0;i<${#s};i++)); do c=${s:i:1}
  case "$c" in [a-zA-Z0-9.~_-]) o="$o$c";; *) o="$o$(printf '%%%02X' "'$c")";; esac; done; printf '%s' "$o"; }
certs_ok(){ [ -s "$CERTS/fullchain.pem" ] && [ -s "$CERTS/private.key" ]; }
cert_hours(){ local e ts; e=$(openssl x509 -in "$CERTS/fullchain.pem" -noout -enddate | cut -d= -f2)
  ts=$(date -d "$e" +%s); echo $(( (ts - $(date +%s)) / 3600 )); }
find_acme_dir(){ local d
  for d in "$ACME_HOME/${SERVER_IP}_ecc" "$ACME_HOME/${SERVER_IP}"; do
    if [ -f "$d/fullchain.cer" ] && [ -f "$d/${SERVER_IP}.key" ]; then printf '%s' "$d"; return 0; fi
  done; return 1; }
test_conf(){ local out
  if out=$("$BIN" run -test -config "$CONF" 2>&1); then return 0; else printf '%s\n' "$out" >&2; return 1; fi; }
port_in_use(){ ss -lnt 2>/dev/null | awk 'NR>1{print $4}' | grep -Eq "[:.]$1$"; }
pick_free_port(){ local p
  for p in $(seq 8080 8199); do
    if [ "$p" != "$PORT" ] && ! port_in_use "$p"; then printf '%s' "$p"; return 0; fi
  done
  printf '8080'; }

# ------------------------------- 依赖 / 内核 -----------------------------------
install_deps(){
  local miss="" p
  for p in curl unzip tar openssl; do command -v "$p" >/dev/null 2>&1 || miss="$miss $p"; done
  if [ -z "$miss" ]; then ok "基础依赖齐全"; return 0; fi
  info "安装依赖:$miss"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y $miss ca-certificates >/dev/null
  elif command -v dnf >/dev/null 2>&1; then dnf install -y $miss ca-certificates >/dev/null
  elif command -v yum >/dev/null 2>&1; then yum install -y $miss ca-certificates >/dev/null
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache $miss ca-certificates >/dev/null
  else die "请手动安装:$miss"; fi
}
detect_arch(){ case "$(uname -m)" in
  x86_64|amd64) echo 64;; i?86) echo 32;; aarch64|arm64) echo arm64-v8a;;
  armv7*) echo arm32-v7a;; armv6*) echo arm32-v6;; riscv64) echo riscv64;;
  s390x) echo s390x;; ppc64le) echo ppc64le;; *) die "不支持的架构 $(uname -m)";; esac; }
latest_ver(){ local v
  v=$(curl -fsSL --max-time 20 https://api.github.com/repos/XTLS/Xray-core/releases/latest \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1) || v=""
  if [ -z "$v" ]; then
    v=$(curl -fsSI --max-time 20 https://github.com/XTLS/Xray-core/releases/latest | tr -d '\r' \
        | sed -n 's#^[Ll]ocation: .*/tag/\(.*\)$#\1#p' | head -n1) || v=""
  fi
  printf '%s' "$v"; }
install_core(){
  local ver="${1:-}" arch tmp url f
  [ -n "$ver" ] || ver=$(latest_ver)
  [ -n "$ver" ] || die "获取 Xray 版本失败，可指定: xray-vless update v25.x.x"
  arch=$(detect_arch); tmp=$(mktemp -d)
  url="https://github.com/XTLS/Xray-core/releases/download/${ver}/Xray-linux-${arch}.zip"
  info "下载 Xray ${ver} (${arch})"
  curl -fL --retry 3 --connect-timeout 15 -o "$tmp/x.zip" "$url" || { rm -rf "$tmp"; die "下载失败"; }
  unzip -q -o "$tmp/x.zip" -d "$tmp/x"; mkdir -p "$SHARE"
  cp -f "$tmp/x/xray" "$BIN.new"; chmod 755 "$BIN.new"; mv -f "$BIN.new" "$BIN"
  for f in geoip.dat geosite.dat; do
    if [ -f "$tmp/x/$f" ]; then cp -f "$tmp/x/$f" "$SHARE/$f.new"; chmod 644 "$SHARE/$f.new"; mv -f "$SHARE/$f.new" "$SHARE/$f"; fi
  done
  rm -rf "$tmp"; ok "内核就绪: $("$BIN" version | head -n1)"
}

# ------------------------------- nginx ----------------------------------------
nginx_bin(){ command -v nginx 2>/dev/null || echo /usr/sbin/nginx; }
nginx_h2_new(){ [ "$(printf '%s\n1.25.1\n' "$1" | sort -V | head -n1)" = "1.25.1" ]; }
install_nginx(){
  local nb; nb=$(nginx_bin)
  if [ ! -x "$nb" ]; then
    info "安装 nginx（仅用其二进制，跑独立实例）"
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y >/dev/null 2>&1 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y nginx >/dev/null
    elif command -v dnf >/dev/null 2>&1; then dnf install -y nginx >/dev/null
    elif command -v yum >/dev/null 2>&1; then yum install -y nginx >/dev/null
    elif command -v apk >/dev/null 2>&1; then apk add --no-cache nginx >/dev/null
    else die "请手动安装 nginx"; fi
    nb=$(nginx_bin)
  fi
  [ -x "$nb" ] || die "nginx 安装失败"
  "$nb" -V 2>&1 | grep -q http_v2_module || die "该 nginx 未编译 http_v2 模块，无法 h2c"
  # 发行版自带实例会抢 80，必须停掉（acme standalone 续期要用 80）
  if systemctl list-unit-files 2>/dev/null | grep -q '^nginx\.service'; then
    if systemctl is-enabled nginx.service >/dev/null 2>&1 || systemctl is-active nginx.service >/dev/null 2>&1; then
      warn "检测到发行版 nginx.service，将停用并取消自启（保护 80 端口给 acme 续期）"
      warn "若你在用它跑别的网站，请先自行迁移；本脚本的实例名为 $FBSVC"
    fi
    systemctl disable --now nginx.service >/dev/null 2>&1 || true
  fi
  ok "nginx 就绪: $("$nb" -v 2>&1)"
}
write_nginx_conf(){
  local nb ver lopt="" listen h2="" mime="" realip="" acclog="access_log off;"
  nb=$(nginx_bin); ver=$("$nb" -v 2>&1 | sed -n 's#.*/##p')
  if [ "$XVER" = 1 ]; then
    lopt=" proxy_protocol"
    realip="set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;"
    acclog="access_log /var/log/xray-fallback.log combined;"
  fi
  if nginx_h2_new "$ver"; then
    listen="listen 127.0.0.1:$WEB_PORT$lopt;"; h2="http2 on;"
  else
    listen="listen 127.0.0.1:$WEB_PORT http2$lopt;"
  fi
  if [ -f /etc/nginx/mime.types ]; then mime="include /etc/nginx/mime.types;"; fi
  cat > "$NGCONF" <<EOF
# 由 xray-vless 自动生成 —— 改端口请用: xray-vless webport <port>
user nobody;
worker_processes 1;
pid /run/xray-fallback-nginx.pid;
error_log stderr warn;
events { worker_connections 1024; }
http {
    $mime
    default_type application/octet-stream;
    $acclog
    server_tokens off;
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    client_max_body_size 1m;
    absolute_redirect off;
    port_in_redirect off;
    server_name_in_redirect off;
    gzip on;
    gzip_vary on;
    gzip_comp_level 5;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml application/json application/javascript image/svg+xml application/xml+rss;
    client_body_temp_path /tmp/xray-fb-body;
    proxy_temp_path /tmp/xray-fb-proxy;
    fastcgi_temp_path /tmp/xray-fb-fastcgi;
    uwsgi_temp_path /tmp/xray-fb-uwsgi;
    scgi_temp_path /tmp/xray-fb-scgi;
    server {
        $listen
        $h2
        server_name _;
        root $WEB_ROOT;
        index index.html;
        $realip
        location / { try_files \$uri \$uri/ =404; }
        location ~ /\. { deny all; }
    }
}
EOF
  if ! "$nb" -t -c "$NGCONF" >/dev/null 2>&1; then "$nb" -t -c "$NGCONF" >&2; die "nginx 配置校验失败"; fi
}
make_site(){
  mkdir -p "$WEB_ROOT"
  if [ ! -f "$WEB_ROOT/index.html" ]; then
    cat > "$WEB_ROOT/index.html" <<'HTML'
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nexus Cloud — Edge Infrastructure</title>
<style>
*{box-sizing:border-box}body{margin:0;font:16px/1.7 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2933;background:#f7f9fc}
header{background:#0f172a;color:#fff;padding:18px 32px;font-weight:600;letter-spacing:.5px}
main{max-width:860px;margin:56px auto;padding:0 24px}h1{font-size:34px;margin:0 0 12px}p{color:#52606d}
.grid{display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin-top:36px}
.card{background:#fff;border:1px solid #e4e7eb;border-radius:10px;padding:20px}
.card h3{margin:0 0 8px;font-size:17px}footer{margin:64px 0 32px;text-align:center;color:#9aa5b1;font-size:13px}
</style></head><body>
<header>NEXUS CLOUD</header>
<main><h1>Edge infrastructure, quietly reliable.</h1>
<p>Regional compute, object storage and anycast DNS for teams that ship. Status: all systems operational.</p>
<div class="grid">
<div class="card"><h3>Compute</h3><p>Deploy in 12 regions with sub-second cold starts.</p></div>
<div class="card"><h3>Storage</h3><p>Durable object storage with global replication.</p></div>
<div class="card"><h3>Network</h3><p>Anycast edge with automatic TLS provisioning.</p></div>
</div></main>
<footer>© Nexus Cloud Ltd. · Terms · Privacy · status.nexuscloud.example</footer>
</body></html>
HTML
  fi
  chmod 755 "$WEB_ROOT"
  find "$WEB_ROOT" -type d -exec chmod 755 {} + 2>/dev/null || true
  find "$WEB_ROOT" -type f -exec chmod 644 {} + 2>/dev/null || true
}

# ------------------------------- Xray 配置 -------------------------------------
build_clients(){
  local out="" id ff=""
  if [ -n "$FLOW" ]; then ff=", \"flow\": \"$FLOW\""; fi
  out="{ \"id\": \"$UUID\"$ff, \"email\": \"main\" }"
  for id in $EXTRA_UUIDS; do out="$out, { \"id\": \"$id\"$ff, \"email\": \"u${id:0:8}\" }"; done
  printf '%s' "$out"
}
alpn_json(){ local out="" a IFS=','
  for a in $ALPN; do if [ -n "$a" ]; then out="$out\"$a\", "; fi; done
  printf '%s' "${out%, }"; }
write_conf(){
  mkdir -p "$ETC" "$CERTS"
  local dest clients alpn rules sniff
  dest=$(dest_now); clients=$(build_clients); alpn=$(alpn_json)
  rules='{ "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }'
  if [ "$BLOCK_BT" = true ]; then rules="$rules, { \"type\": \"field\", \"protocol\": [\"bittorrent\"], \"outboundTag\": \"block\" }"; fi
  if [ "$BLOCK_ADS" = true ]; then rules="$rules, { \"type\": \"field\", \"domain\": [\"geosite:category-ads-all\"], \"outboundTag\": \"block\" }"; fi
  if [ "$SNIFF" = true ]; then sniff='{ "enabled": true, "destOverride": ["http","tls","quic"], "routeOnly": true }'
  else sniff='{ "enabled": false }'; fi
  cat > "$CONF" <<EOF
{
  "log": { "loglevel": "$LOG_LEVEL" },
  "inbounds": [
    {
      "tag": "vless-tcp-tls-vision",
      "listen": "0.0.0.0",
      "port": $PORT,
      "protocol": "vless",
      "settings": {
        "clients": [ $clients ],
        "decryption": "none",
        "fallbacks": [
          { "dest": "$dest", "xver": $XVER }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": [ $alpn ],
          "minVersion": "$MIN_TLS",
          "rejectUnknownSni": false,
          "certificates": [
            { "certificateFile": "$CERTS/fullchain.pem", "keyFile": "$CERTS/private.key" }
          ]
        }
      },
      "sniffing": $sniff
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "UseIPv4" } },
    { "tag": "block", "protocol": "blackhole", "settings": {} }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [ $rules ]
  }
}
EOF
  chmod 644 "$CONF"
}
write_units(){
  cat > "$UNIT" <<EOF
[Unit]
Description=Xray VLESS + TCP + TLS + XTLS Vision
Documentation=https://xtls.github.io/
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$BIN run -config $CONF
Restart=on-failure
RestartSec=3
RestartPreventExitStatus=23
LimitNOFILE=1048576
LimitNPROC=10000
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  local nb; nb=$(nginx_bin)
  cat > "$FBUNIT" <<EOF
[Unit]
Description=Xray fallback web (nginx h2c, loopback only)
After=network.target

[Service]
Type=simple
ExecStartPre=$nb -t -c $NGCONF
ExecStart=$nb -c $NGCONF -g "daemon off;"
ExecReload=$nb -c $NGCONF -s reload
Restart=always
RestartSec=2
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
}

# ------------------------------- 应用 ------------------------------------------
apply(){
  save
  if [ -f "$CONF" ]; then cp -f "$CONF" "$CONF.bak"; fi
  if [ "$DEST_MODE" = local ]; then install_nginx; make_site; write_nginx_conf; fi
  write_conf
  if ! test_conf; then
    if [ -f "$CONF.bak" ]; then cp -f "$CONF.bak" "$CONF"; warn "已回滚 config.json"; fi
    die "Xray 配置校验失败"
  fi
  write_units; systemctl daemon-reload
  if [ "$DEST_MODE" = local ]; then
    systemctl enable "$FBSVC" >/dev/null 2>&1 || true
    systemctl restart "$FBSVC"; sleep 0.5
    if ! systemctl is-active --quiet "$FBSVC"; then
      journalctl -u "$FBSVC" -n 20 --no-pager >&2; die "nginx 回落启动失败"
    fi
  else
    systemctl disable --now "$FBSVC" >/dev/null 2>&1 || true
  fi
  if ! certs_ok; then
    warn "证书缺失，Xray 未启动。执行: xray-vless cert hook  之后再 start"
    return 0
  fi
  systemctl enable "$SVC" >/dev/null 2>&1 || true
  systemctl restart "$SVC"; sleep 1
  if systemctl is-active --quiet "$SVC"; then
    ok "Xray :$PORT  |  nginx 回落 $(dest_now)  |  ALPN $ALPN"
  else
    journalctl -u "$SVC" -n 25 --no-pager >&2; die "Xray 启动失败"
  fi
}
verify_stack(){
  local v e
  if [ "$DEST_MODE" = local ] && [ "$XVER" = 0 ] && curl -V 2>/dev/null | grep -q HTTP2; then
    v=$(curl -s -o /dev/null -w '%{http_version}:%{http_code}' --http2-prior-knowledge --max-time 6 "http://127.0.0.1:$WEB_PORT/" || true)
    case "$v" in 2:*) ok "nginx h2c 正常 ($v)";; *) warn "nginx h2c 异常 (${v:-无响应})";; esac
  fi
  if [ -n "$SERVER_IP" ] && certs_ok; then
    e=$(curl -s -o /dev/null -w '%{http_version}:%{http_code}' --max-time 8 "$(https_url)" || true)
    case "$e" in 2:200|2:301|2:302) ok "公网 $(https_url) → HTTP/2，证书校验通过 ($e)";;
      *) warn "公网伪装站检查: ${e:-无响应}";; esac
  fi
}
open_firewall(){
  local p="$1"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ufw allow "$p"/tcp >/dev/null 2>&1; then ok "ufw 已放行 $p/tcp"; fi
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$p"/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "firewalld 已放行 $p/tcp"
  else
    info "若使用 iptables / 云安全组，请自行放行 $p/tcp"
  fi
}

# ------------------------------- 生命周期 --------------------------------------
cmd_install(){
  need_root; need_systemd; install_deps
  local fresh=0; if [ ! -f "$STATE" ]; then fresh=1; fi
  load
  if [ -z "$SERVER_IP" ]; then SERVER_IP=$(detect_ip); fi
  [ -n "$SERVER_IP" ] || die "探测公网 IP 失败: xray-vless set SERVER_IP <IP>"
  if [ -z "$UUID" ]; then UUID=$(gen_uuid); fi
  install_core "${1:-}"
  if [ "$fresh" = 1 ] || port_in_use "$WEB_PORT"; then
    if [ "$fresh" = 1 ] || [ "$WEB_PORT" = "$PORT" ]; then WEB_PORT=$(pick_free_port); info "后端 Web 端口自动选择: $WEB_PORT"; fi
  fi
  if ! certs_ok; then
    if find_acme_dir >/dev/null 2>&1; then cert_copy_quiet; else warn "未在 $ACME_HOME 找到 $SERVER_IP 的证书"; fi
  fi
  apply
  if find_acme_dir >/dev/null 2>&1; then cmd_cert_hook || true; fi
  open_firewall "$PORT"
  echo; cmd_info; echo; verify_stack; echo
  info "端口: $PORT/tcp 代理 | 80/tcp 必须开放且留空(acme 续期) | 127.0.0.1:$WEB_PORT 后端 nginx"
}
cmd_uninstall(){
  need_root; load
  if [ "${2:-}" != "-y" ]; then read -r -p "确认卸载? [y/N] " a; [ "$a" = y ] || return 0; fi
  systemctl disable --now "$SVC" >/dev/null 2>&1 || true
  systemctl disable --now "$FBSVC" >/dev/null 2>&1 || true
  rm -f "$UNIT" "$FBUNIT"; systemctl daemon-reload; rm -f "$BIN" "$BIN.bak"
  if [ "${1:-}" = "--purge" ]; then
    rm -rf "$ETC" "$SHARE" "$WEB_ROOT"; ok "已彻底删除（acme.sh 原始证书未动，nginx 软件包保留）"
  else ok "已卸载，配置保留在 $ETC"; fi
}
cmd_start(){ need_root; load
  if [ "$DEST_MODE" = local ]; then systemctl start "$FBSVC"; fi
  certs_ok || die "证书缺失，先 cert hook"; test_conf || die "配置错误"
  systemctl start "$SVC"; sleep 1; cmd_status; }
cmd_stop(){ need_root; systemctl stop "$SVC"; ok "Xray 已停止"
  if [ "${1:-}" = all ]; then systemctl stop "$FBSVC"; ok "nginx 回落已停止"; fi; }
cmd_restart(){ need_root; load; test_conf || die "配置错误"
  if [ "$DEST_MODE" = local ]; then "$(nginx_bin)" -t -c "$NGCONF" >/dev/null 2>&1 || die "nginx 配置错误"; systemctl restart "$FBSVC"; fi
  systemctl restart "$SVC"; sleep 1; cmd_status; }
cmd_status(){
  systemctl --no-pager -l status "$SVC" | head -n 10 || true; echo "----"
  systemctl --no-pager -l status "$FBSVC" | head -n 6 || true; echo "----"
  ss -lntp 2>/dev/null | grep -E "[:.](${PORT}|${WEB_PORT}|80)\b" || true
}

# ------------------------------- 端口 ------------------------------------------
cmd_port(){
  need_root; load
  local p="${1:-}" old
  if [ -z "$p" ]; then read -r -p "当前 Xray 端口 $PORT，新端口: " p; fi
  { [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ]; } || die "端口非法"
  [ "$p" != 80 ] || die "80 必须留给 acme standalone 续期"
  [ "$p" != "$WEB_PORT" ] || die "与后端 Web 端口 $WEB_PORT 冲突"
  if [ "$p" = "$PORT" ]; then info "端口未变化"; return 0; fi
  if port_in_use "$p"; then err "端口 $p 已被占用:"; ss -lntp | grep -E "[:.]$p\b" || true; die "换一个"; fi
  old="$PORT"; PORT="$p"
  if ( apply ); then open_firewall "$p"; ok "Xray 端口 $old → $PORT"; cmd_link
  else PORT="$old"; warn "回滚到 $old"; apply || true; die "切换失败"; fi
}
cmd_webport(){
  need_root; load
  local p="${1:-}" old
  if [ -z "$p" ]; then read -r -p "当前后端 Web 端口 $WEB_PORT，新端口(或 auto): " p; fi
  if [ "$p" = auto ]; then p=$(pick_free_port); info "自动选择空闲端口: $p"; fi
  { [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1024 ] && [ "$p" -le 65535 ]; } || die "端口非法（建议 1024-65535）"
  [ "$p" != 80 ] || die "80 必须留给 acme 续期"
  [ "$p" != "$PORT" ] || die "不能与 Xray 端口 $PORT 相同"
  if [ "$p" = "$WEB_PORT" ]; then info "端口未变化"; return 0; fi
  if port_in_use "$p"; then err "端口 $p 已被占用:"; ss -lntp | grep -E "[:.]$p\b" || true; die "换一个"; fi
  old="$WEB_PORT"; WEB_PORT="$p"; DEST_MODE=local
  if ( apply ); then
    ok "后端 Web 端口 $old → $WEB_PORT"
    ok "已同步: nginx listen 127.0.0.1:$WEB_PORT  ←→  config.json fallbacks.dest"
    verify_stack
  else WEB_PORT="$old"; warn "回滚到 $old"; apply || true; die "切换失败"; fi
}
cmd_dest(){
  need_root; load
  local mode="${1:-show}" d="${2:-}"
  case "$mode" in
    local) DEST_MODE=local; apply; ok "回落 → 本机 nginx 127.0.0.1:$WEB_PORT (h2c)"; verify_stack;;
    remote)
      [ -n "$d" ] || die "用法: dest remote <host[:port]>"
      d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"
      case "$d" in *:*) ;; *) d="$d:80";; esac
      REMOTE_DEST="$d"; DEST_MODE=remote
      case ",$ALPN," in *,h2,*)
        warn "外部站点 :80 基本不支持 h2c，ALPN 含 h2 会让浏览器直连失败"
        warn "建议: dest local  或  set ALPN http/1.1" ;;
      esac
      apply; ok "回落 → $REMOTE_DEST（nginx 实例已停用）";;
    show) echo "模式: $DEST_MODE"; echo "dest: $(dest_now)"; echo "站点目录: $WEB_ROOT"; echo "xver: $XVER";;
    *) die "用法: dest local | dest remote <host:port> | dest show";;
  esac
}
cmd_webroot(){ need_root; load; WEB_ROOT="${1:?用法: webroot <目录>}"; DEST_MODE=local; apply; ok "站点目录 → $WEB_ROOT"; verify_stack; }
cmd_proxy(){
  need_root; load
  case "${1:-status}" in
    on) XVER=1; DEST_MODE=local; apply; ok "PROXY 协议已开启 (xver=1 + nginx proxy_protocol)，真实 IP 记入 /var/log/xray-fallback.log";;
    off) XVER=0; apply; ok "PROXY 协议已关闭";;
    status) echo "xver=$XVER";;
    *) die "用法: proxy on|off|status";;
  esac
}

# ------------------------------- 用户 ------------------------------------------
cmd_uuid(){ need_root; load; local new="${1:-}"
  if [ -z "$new" ]; then new=$(gen_uuid); fi
  is_uuid "$new" || die "UUID 格式不合法"; UUID="$new"; apply; ok "主 UUID 已更换"; cmd_link; }
cmd_user(){
  need_root; load
  local act="${1:-list}" id="${2:-}" out="" x
  case "$act" in
    add) if [ -z "$id" ]; then id=$(gen_uuid); fi
      is_uuid "$id" || die "UUID 不合法"
      case " $UUID $EXTRA_UUIDS " in *" $id "*) die "已存在";; esac
      EXTRA_UUIDS="$(printf '%s %s' "$EXTRA_UUIDS" "$id" | sed 's/^ *//')"; apply; ok "已添加 $id"; cmd_link "$id";;
    del) [ -n "$id" ] || die "用法: user del <uuid>"
      [ "$id" != "$UUID" ] || die "主 UUID 请用 uuid 命令"
      for x in $EXTRA_UUIDS; do if [ "$x" != "$id" ]; then out="$out $x"; fi; done
      EXTRA_UUIDS="$(printf '%s' "$out" | sed 's/^ *//')"; apply; ok "已删除 $id";;
    list) echo "主用户: $UUID"; for x in $EXTRA_UUIDS; do echo "附加:   $x"; done;;
    *) die "用法: user add|del|list";;
  esac
}
cmd_set(){
  need_root; load
  local k="${1:-}" v="${2:-}"
  [ -n "$k" ] || die "用法: set <KEY> <VALUE>"
  case "$k" in
    MIN_TLS) case "$v" in 1.2|1.3) ;; *) die "1.2 / 1.3";; esac;;
    LOG_LEVEL) case "$v" in debug|info|warning|error|none) ;; *) die "debug/info/warning/error/none";; esac;;
    BLOCK_BT|BLOCK_ADS|SNIFF) case "$v" in true|false) ;; *) die "true/false";; esac;;
    DEST_MODE) case "$v" in local|remote) ;; *) die "local/remote";; esac;;
    FLOW) case "$v" in xtls-rprx-vision) ;; none) v="";; *) die "xtls-rprx-vision / none";; esac;;
    ALPN|REMARK|CLIENT_FP|SERVER_IP|REMOTE_DEST|ACME_HOME|WEB_ROOT) ;;
    PORT|WEB_PORT) die "请用 port / webport 命令";;
    UUID|EXTRA_UUIDS) die "请用 uuid / user 命令";;
    *) die "不支持的参数: $k";;
  esac
  v="${v//\'/}"; printf -v "$k" '%s' "$v"; apply; ok "$k = $v"
}

# ------------------------------- 证书 ------------------------------------------
cert_copy_quiet(){ local d; d=$(find_acme_dir) || return 1
  mkdir -p "$CERTS"
  install -m 644 "$d/fullchain.cer" "$CERTS/fullchain.pem"
  install -m 600 "$d/${SERVER_IP}.key" "$CERTS/private.key"
  ok "已从 $d 复制证书"; }
cmd_cert_hook(){
  need_root; load
  local acme="$ACME_HOME/acme.sh" d ecc=""
  if [ ! -x "$acme" ]; then acme=$(command -v acme.sh || true); fi
  [ -n "$acme" ] || die "找不到 acme.sh，请 set ACME_HOME <路径>"
  if d=$(find_acme_dir); then case "$d" in *_ecc) ecc="--ecc";; esac; fi
  if [ "${1:-}" = "--ecc" ]; then ecc="--ecc"; elif [ "${1:-}" = "--rsa" ]; then ecc=""; fi
  mkdir -p "$CERTS"
  "$acme" --install-cert -d "$SERVER_IP" $ecc \
    --fullchain-file "$CERTS/fullchain.pem" --key-file "$CERTS/private.key" \
    --reloadcmd "systemctl restart $SVC"
  chmod 644 "$CERTS/fullchain.pem" 2>/dev/null || true
  chmod 600 "$CERTS/private.key" 2>/dev/null || true
  ok "续期后自动装证书 + 重启 Xray 已配置"
  systemctl restart "$SVC" 2>/dev/null || true
}
cmd_cert_info(){
  load; certs_ok || die "证书不存在"
  openssl x509 -in "$CERTS/fullchain.pem" -noout -subject -issuer -dates -ext subjectAltName
  echo "---- 剩余 $(cert_hours) 小时"
  local c="$ACME_HOME/${SERVER_IP}_ecc/${SERVER_IP}.conf"
  if [ ! -f "$c" ]; then c="$ACME_HOME/${SERVER_IP}/${SERVER_IP}.conf"; fi
  if [ -f "$c" ]; then grep -E 'Le_ReloadCmd|Le_NextRenewTimeStr' "$c" || true; fi
}
cmd_cert(){ case "${1:-info}" in
  hook) shift; cmd_cert_hook "$@";; copy) need_root; load; cert_copy_quiet || die "未找到证书"; apply;;
  info) cmd_cert_info;; *) die "用法: cert hook|copy|info";; esac; }

# ------------------------------- 输出 ------------------------------------------
build_link(){ load; local id="${1:-$UUID}" rm="${2:-$REMARK}" fp=""
  if [ -n "$FLOW" ]; then fp="&flow=$FLOW"; fi
  printf 'vless://%s@%s:%s?encryption=none%s&security=tls&sni=%s&alpn=%s&fp=%s&type=tcp&headerType=none#%s' \
    "$id" "$SERVER_IP" "$PORT" "$fp" "$SERVER_IP" "$(urlencode "$ALPN")" "$CLIENT_FP" "$(urlencode "$rm")"; }
cmd_link(){ load; local l; l=$(build_link "${1:-}"); echo; echo "${G}$l${N}"; echo
  if command -v qrencode >/dev/null 2>&1; then qrencode -t ANSIUTF8 "$l"; else info "装 qrencode 可显示二维码"; fi; }
cmd_info(){
  load
  echo "============ Xray VLESS + TCP + TLS + Vision (v$SCRIPT_VER) ============"
  printf '  地址(SNI)  : %s\n  代理端口   : %s\n  UUID       : %s\n  Flow       : %s\n' "$SERVER_IP" "$PORT" "$UUID" "${FLOW:-none}"
  printf '  TLS        : min %s | alpn %s\n' "$MIN_TLS" "$ALPN"
  printf '  后端 Web   : %s  (%s)\n' "$(dest_now)" "$DEST_MODE"
  printf '  站点目录   : %s\n  PROXY协议  : xver=%s\n' "$WEB_ROOT" "$XVER"
  if certs_ok; then printf '  证书剩余   : %s 小时\n' "$(cert_hours)"; else printf '  证书剩余   : 缺失!\n'; fi
  printf '  服务状态   : xray=%s nginx=%s\n' "$(systemctl is-active "$SVC" 2>/dev/null || echo unknown)" "$(systemctl is-active "$FBSVC" 2>/dev/null || echo unknown)"
  echo "======================================================================"
  cmd_link
  local x; for x in $EXTRA_UUIDS; do echo; echo "附加用户 $x:"; cmd_link "$x"; done
}
cmd_client(){ load
  cat <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
      "settings": { "udp": true }, "sniffing": { "enabled": true, "destOverride": ["http","tls"] } }
  ],
  "outbounds": [
    { "tag": "proxy", "protocol": "vless",
      "settings": { "vnext": [ { "address": "$SERVER_IP", "port": $PORT,
        "users": [ { "id": "$UUID", "encryption": "none", "flow": "$FLOW" } ] } ] },
      "streamSettings": { "network": "tcp", "security": "tls",
        "tlsSettings": { "serverName": "$SERVER_IP", "alpn": [ $(alpn_json) ],
          "fingerprint": "$CLIENT_FP", "allowInsecure": false } } },
    { "tag": "direct", "protocol": "freedom" }
  ],
  "routing": { "domainStrategy": "IPIfNonMatch",
    "rules": [ { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" } ] }
}
EOF
}

# ------------------------------- 运维 ------------------------------------------
cmd_logs(){ case "${1:-}" in
  -f) journalctl -u "$SVC" -f;; web) journalctl -u "$FBSVC" -n 100 --no-pager;;
  *) journalctl -u "$SVC" -n 100 --no-pager;; esac; }
cmd_update(){
  need_root; load
  local cur="unknown" ver="${1:-}"
  if [ -x "$BIN" ]; then cur=$("$BIN" version | head -n1 | awk '{print $2}'); cp -f "$BIN" "$BIN.bak"; fi
  if [ -z "$ver" ]; then ver=$(latest_ver); fi
  [ -n "$ver" ] || die "获取版本失败"
  info "v$cur → $ver"; install_core "$ver"
  if ! test_conf; then if [ -f "$BIN.bak" ]; then mv -f "$BIN.bak" "$BIN"; fi; die "校验失败，已回滚"; fi
  systemctl restart "$SVC"; sleep 1; ok "升级完成: $("$BIN" version | head -n1)"
}
cmd_geo(){ need_root; local tmp; tmp=$(mktemp -d)
  curl -fL --retry 3 -o "$tmp/geoip.dat" https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
  curl -fL --retry 3 -o "$tmp/geosite.dat" https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
  mkdir -p "$SHARE"; mv -f "$tmp/geoip.dat" "$SHARE/geoip.dat"; mv -f "$tmp/geosite.dat" "$SHARE/geosite.dat"
  chmod 644 "$SHARE"/*.dat; rm -rf "$tmp"; systemctl restart "$SVC"; ok "geo 数据已更新"; }
cmd_bbr(){ need_root
  cat > /etc/sysctl.d/99-xray-tune.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_mtu_probing = 1
EOF
  sysctl --system >/dev/null 2>&1 || true
  ok "拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"; }
cmd_backup(){ load; local f="/root/xray-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  tar czf "$f" --ignore-failed-read -C / usr/local/etc/xray "${WEB_ROOT#/}" 2>/dev/null || tar czf "$f" -C / usr/local/etc/xray
  ok "备份: $f"; }
cmd_restore(){ need_root; local f="${1:?用法: restore <备份.tar.gz>}"
  [ -f "$f" ] || die "文件不存在"; tar xzf "$f" -C /; load; apply; ok "已恢复"; }
cmd_doctor(){
  load; local bad=0 code h ac v
  echo "================ 自检 ================"
  if [ -x "$BIN" ]; then ok "$("$BIN" version | head -n1)"; else err "缺少 xray"; bad=1; fi
  if [ -f "$CONF" ] && test_conf >/dev/null 2>&1; then ok "config.json 校验通过"; else err "config.json 校验失败"; bad=1; fi
  if systemctl is-active --quiet "$SVC"; then ok "xray.service 运行中"; else err "xray.service 未运行"; bad=1; fi
  if port_in_use "$PORT"; then ok "TCP $PORT 正在监听"; else err "TCP $PORT 未监听"; bad=1; fi
  if [ "$DEST_MODE" = local ]; then
    if systemctl is-active --quiet "$FBSVC"; then ok "nginx 回落实例运行中"; else err "nginx 回落未运行"; bad=1; fi
    if "$(nginx_bin)" -t -c "$NGCONF" >/dev/null 2>&1; then ok "nginx 配置校验通过 ($("$(nginx_bin)" -v 2>&1))"; else err "nginx 配置有误"; bad=1; fi
    if grep -q "\"dest\": \"127.0.0.1:$WEB_PORT\"" "$CONF"; then ok "端口联动一致: dest=127.0.0.1:$WEB_PORT"; else err "config.json 的 dest 与 WEB_PORT 不一致 → xray-vless apply"; bad=1; fi
    if [ "$XVER" = 0 ] && curl -V 2>/dev/null | grep -q HTTP2; then
      v=$(curl -s -o /dev/null -w '%{http_version}:%{http_code}' --http2-prior-knowledge --max-time 6 "http://127.0.0.1:$WEB_PORT/" || true)
      case "$v" in 2:*) ok "nginx h2c 正常 ($v)";; *) err "h2c 异常 (${v:-none})，ALPN 的能力与后端不一致"; bad=1;; esac
    fi
  fi
  if certs_ok; then
    h=$(cert_hours)
    if [ "$h" -gt 24 ]; then ok "证书剩余 $h 小时"; else err "证书仅剩 $h 小时 → acme.sh --cron"; bad=1; fi
    if openssl x509 -in "$CERTS/fullchain.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "$SERVER_IP"; then ok "证书 SAN 含 $SERVER_IP"; else err "证书 SAN 不含 $SERVER_IP"; bad=1; fi
  else err "证书缺失"; bad=1; fi
  ac="$ACME_HOME/${SERVER_IP}_ecc/${SERVER_IP}.conf"
  if [ ! -f "$ac" ]; then ac="$ACME_HOME/${SERVER_IP}/${SERVER_IP}.conf"; fi
  if [ -f "$ac" ] && grep -q 'Le_ReloadCmd=.*xray' "$ac"; then ok "acme 续期后自动重启 Xray"; else warn "未检测到 reloadcmd → cert hook"; fi
  if port_in_use 80; then warn "80 被占用！standalone(socat) 续期会失败"; ss -lntp | grep ':80 ' || true; else ok "80 空闲（续期通道正常）"; fi
  code=$(curl -s -o /dev/null -w '%{http_version}:%{http_code}' --max-time 8 "$(https_url)" || true)
  case "$code" in *:200|*:301|*:302) ok "伪装站 $(https_url) → $code";; *) warn "伪装站检查: ${code:-无响应}";; esac
  if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" = bbr ]; then ok "BBR 已开启"; else warn "BBR 未开启 → bbr"; fi
  echo "======================================"
  if [ "$bad" = 0 ]; then ok "全部关键项通过"; else err "存在关键问题"; fi
}

# ------------------------------- 菜单 ------------------------------------------
cmd_menu(){
  load
  while true; do
    echo; echo "${B}===== Xray VLESS+TCP+TLS+Vision v$SCRIPT_VER =====${N}"
    cmd_info | head -n 13
    cat <<'MENU'
 1) 启动   2) 停止   3) 重启   4) 状态
 5) 更换 UUID              6) 更换后端网站(回落)
 7) 更改 Xray 监听端口     8) 更改后端 Web 端口
 9) 用户管理(多 UUID)     10) 证书对接/查看
11) 自检 doctor           12) 升级内核
13) 更新 geo              14) 开启 BBR
15) 备份                  16) 更改站点目录
17) PROXY 协议 on/off     18) 查看 nginx 日志
 0) 退出
MENU
    read -r -p "选择: " c
    case "$c" in
      1) cmd_start;; 2) cmd_stop;; 3) cmd_restart;; 4) cmd_status;;
      5) cmd_uuid;;
      6) read -r -p "local 或 remote host:port → " a b; cmd_dest "$a" "${b:-}";;
      7) cmd_port;; 8) cmd_webport;;
      9) read -r -p "add [uuid] / del <uuid> / list → " a b; cmd_user "$a" "${b:-}";;
      10) read -r -p "hook / copy / info → " a; cmd_cert "$a";;
      11) cmd_doctor;; 12) cmd_update;; 13) cmd_geo;; 14) cmd_bbr;; 15) cmd_backup;;
      16) read -r -p "站点目录: " d; cmd_webroot "$d";;
      17) read -r -p "on / off / status → " a; cmd_proxy "$a";;
      18) cmd_logs web;;
      0) exit 0;; *) warn "无效选择";;
    esac
  done
}
usage(){
cat <<'USAGE'
Xray VLESS+TCP+TLS+XTLS Vision 管理脚本 v2.0（nginx h2c 后端全自动）

  install [version] | uninstall [--purge] [-y]
  start | stop [all] | restart | status | enable | disable
  port [端口]         更改 Xray 对外监听端口
  webport <端口|auto> 更改后端 nginx 端口（自动同步写入 config.json 的 dest）
  webroot <目录>      更换伪装站目录
  dest local | dest remote <host:port> | dest show
  proxy on|off        PROXY 协议(xver=1)，让 nginx 日志记录真实客户端 IP
  uuid [uuid] | user add|del|list
  set <KEY> <VALUE>   ALPN/MIN_TLS/LOG_LEVEL/FLOW/BLOCK_BT/BLOCK_ADS/SNIFF/REMARK...
  cert hook|copy|info | link | info | client | logs [-f|web] | doctor
  update [version] | geo | bbr | backup | restore <file> | menu
USAGE
}
main(){
  local cmd="${1:-menu}"; shift || true
  case "$cmd" in
    install) cmd_install "$@";; uninstall) cmd_uninstall "$@";;
    start) cmd_start;; stop) cmd_stop "$@";; restart) cmd_restart;; status) cmd_status;;
    enable) need_root; systemctl enable "$SVC" "$FBSVC";; disable) need_root; systemctl disable "$SVC" "$FBSVC";;
    port) cmd_port "$@";; webport) cmd_webport "$@";; webroot) cmd_webroot "$@";;
    dest) cmd_dest "$@";; proxy) cmd_proxy "$@";;
    uuid) cmd_uuid "$@";; user) cmd_user "$@";; set) cmd_set "$@";;
    apply) need_root; load; apply; verify_stack;;
    cert) cmd_cert "$@";; link) cmd_link "$@";; info) cmd_info;; client) cmd_client;;
    logs) cmd_logs "$@";; doctor) cmd_doctor;;
    update) cmd_update "$@";; geo) cmd_geo;; bbr) cmd_bbr;;
    backup) cmd_backup;; restore) cmd_restore "$@";;
    menu) cmd_menu;; -h|--help|help) usage;; version) echo "$SCRIPT_VER";;
    *) usage; exit 1;;
  esac
}
main "$@"
