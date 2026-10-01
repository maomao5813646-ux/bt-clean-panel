#!/bin/bash
set +e

PANEL_PATH="/www/server/panel"
NGINX_VHOST_DIR="${PANEL_PATH}/vhost/nginx"
WWW_LOG_DIR="/www/wwwlogs"
MODE="${1:-full}"
NGINX_TXN_BACKUP=""

log_msg() {
    echo "[bt-clean-cpu-guard] $*"
}

quarantine_known_mobile_redirect_backdoor() {
    proxy_conf="/www/server/nginx/conf/proxy.conf"
    injected_lua="/www/server/nginx/html/waf.lua"
    known_hash="212aa15c51ea08f3f2cbd57e475a2baaeb4a0771b921b517a9c0795314bad210"
    file_hash="$(sha256sum "${injected_lua}" 2>/dev/null | awk '{print $1}')"
    injected=0
    suspicious=0
    grep -qE '^[[:space:]]*(access|body_filter|header_filter)_by_lua_file[[:space:]]+/www/server/nginx/html/waf\.lua;[[:space:]]*$' "${proxy_conf}" 2>/dev/null && injected=1
    [ -e "${injected_lua}" ] && suspicious=1
    if [ "${injected}" -eq 0 ] && [ "${suspicious}" -eq 0 ]; then
        if [ -f "${proxy_conf}" ] && grep -qE '^[[:space:]]*lua_shared_dict[[:space:]]+my_cache[[:space:]]+10m;' "${proxy_conf}"; then
            chattr -i -a "${proxy_conf}" >/dev/null 2>&1 || true
            sed -i '\#^[[:space:]]*lua_shared_dict[[:space:]]\+my_cache[[:space:]]\+10m;[[:space:]]*$#d' "${proxy_conf}"
        fi
        return 0
    fi

    quarantine="/root/btclean_quarantine_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "${quarantine}"
    chattr -i -a "${proxy_conf}" "${injected_lua}" 2>/dev/null || true
    if [ -f "${injected_lua}" ]; then
        printf '%s  removed_darkjump_payload\n' "${file_hash}" > "${quarantine}/REMOVED_SHA256SUMS"
    fi

    if [ -f "${proxy_conf}" ]; then
        sed -i \
            -e '\#^[[:space:]]*lua_shared_dict[[:space:]]\+my_cache[[:space:]]\+10m;[[:space:]]*$#d' \
            -e '\#^[[:space:]]*\(access\|body_filter\|header_filter\)_by_lua_file[[:space:]]\+/www/server/nginx/html/waf\.lua;[[:space:]]*$#d' \
            "${proxy_conf}"
    fi
    [ -f "${injected_lua}" ] && { shred -u "${injected_lua}" 2>/dev/null || rm -f "${injected_lua}"; }
    log_msg "quarantined injected mobile redirect backdoor: ${quarantine}"
}

quarantine_usbnotify_persistence() {
    binary="/usr/sbin/usbnotify"
    found=0
    [ -e "${binary}" ] && found=1
    for unit in /etc/systemd/system/usbnotify.service /lib/systemd/system/usbnotify.service /usr/lib/systemd/system/usbnotify.service; do
        [ -e "${unit}" ] || continue
        [ "$(readlink -f "${unit}" 2>/dev/null)" = "/dev/null" ] || found=1
    done
    [ "${found}" -eq 1 ] || return 0

    quarantine="/root/btclean_quarantine_$(date +%Y%m%d_%H%M%S)_usbnotify"
    mkdir -p "${quarantine}"
    systemctl disable --now usbnotify.service >/dev/null 2>&1 || true
    systemctl mask usbnotify.service >/dev/null 2>&1 || true
    pkill -9 -f '(^|/)usbnotify([[:space:]]|$)' >/dev/null 2>&1 || true
    chattr -i -a "${binary}" >/dev/null 2>&1 || true
    if [ -e "${binary}" ]; then
        sha256sum "${binary}" 2>/dev/null | awk '{print $1 "  removed_usbnotify_payload"}' > "${quarantine}/REMOVED_SHA256SUMS" || true
        shred -u "${binary}" 2>/dev/null || rm -f "${binary}"
    fi
    for unit in /etc/systemd/system/usbnotify.service /lib/systemd/system/usbnotify.service /usr/lib/systemd/system/usbnotify.service; do
        [ -e "${unit}" ] || continue
        chattr -i -a "${unit}" >/dev/null 2>&1 || true
        rm -f "${unit}"
    done
    rm -f /etc/systemd/system/multi-user.target.wants/usbnotify.service
    ln -sf /dev/null /etc/systemd/system/usbnotify.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    log_msg "disabled and quarantined usbnotify persistence: ${quarantine}"
}

purge_known_darkjump_artifacts() {
    find /www/server/nginx/conf -maxdepth 1 -type f -name 'proxy.conf.bak*' 2>/dev/null | while read -r old; do
        if grep -qE '(access|body_filter|header_filter)_by_lua_file[[:space:]]+/www/server/nginx/html/waf\.lua|hy4jl8794jklfds|k593turiofmkqw' "${old}" 2>/dev/null; then
            chattr -i -a "${old}" >/dev/null 2>&1 || true
            rm -f "${old}"
        fi
    done
    find /root -maxdepth 2 -type f \( -path '/root/btclean_quarantine_*/*' -o -path '/root/bt-clean-quarantine-*/*' \) 2>/dev/null | while read -r sample; do
        if grep -qE 'access_by_lua_file[[:space:]]+/www/server/nginx/html/waf\.lua|hy4jl8794jklfds|k593turiofmkqw|lmth\.naim/(evil|pot|uoyc)|ngx\.redirect' "${sample}" 2>/dev/null; then
            chattr -i -a "${sample}" >/dev/null 2>&1 || true
            shred -u "${sample}" 2>/dev/null || rm -f "${sample}"
            continue
        fi
        case "$(basename "${sample}")" in
            waf.lua|waf.lua.quarantined|legacy_darkjump_waf.lua|usbnotify|usbnotify.quarantined)
                chattr -i -a "${sample}" >/dev/null 2>&1 || true
                shred -u "${sample}" 2>/dev/null || rm -f "${sample}"
                ;;
        esac
    done
}

begin_nginx_transaction() {
    [ -d "${NGINX_VHOST_DIR}" ] || return 0
    backup_root="/www/backup/bt-clean-nginx"
    NGINX_TXN_BACKUP="${backup_root}/$(date +%Y%m%d_%H%M%S)_$$"
    mkdir -p "${NGINX_TXN_BACKUP}/vhost"
    find "${NGINX_VHOST_DIR}" -maxdepth 1 -type f -name "*.conf" -exec cp -a {} "${NGINX_TXN_BACKUP}/vhost/" \;
    find "${NGINX_VHOST_DIR}" -maxdepth 1 -type f -name "*.conf" -printf "%f\n" > "${NGINX_TXN_BACKUP}/vhost.manifest"
    [ -d "${NGINX_VHOST_DIR}/guard" ] && cp -a "${NGINX_VHOST_DIR}/guard" "${NGINX_TXN_BACKUP}/guard"
    [ -d "${PANEL_PATH}/vhost/rewrite" ] && cp -a "${PANEL_PATH}/vhost/rewrite" "${NGINX_TXN_BACKUP}/rewrite"
    [ -d "${NGINX_VHOST_DIR}/proxy" ] && cp -a "${NGINX_VHOST_DIR}/proxy" "${NGINX_TXN_BACKUP}/proxy"
    [ -f /www/server/nginx/conf/nginx.conf ] && cp -a /www/server/nginx/conf/nginx.conf "${NGINX_TXN_BACKUP}/nginx.conf"
    find "${backup_root}" -mindepth 1 -maxdepth 1 -type d -printf "%T@ %p\n" 2>/dev/null | sort -nr | awk 'NR>10 {$1=""; sub(/^ /, ""); print}' | while read -r old; do
        [ -n "${old}" ] && rm -rf -- "${old}"
    done
    log_msg "nginx backup: ${NGINX_TXN_BACKUP}"
}

rollback_nginx_transaction() {
    [ -n "${NGINX_TXN_BACKUP}" ] && [ -d "${NGINX_TXN_BACKUP}" ] || return 1
    [ -f "${NGINX_TXN_BACKUP}/nginx.conf" ] && cp -a "${NGINX_TXN_BACKUP}/nginx.conf" /www/server/nginx/conf/nginx.conf
    for conf in "${NGINX_TXN_BACKUP}"/vhost/*.conf; do
        [ -f "${conf}" ] && cp -a "${conf}" "${NGINX_VHOST_DIR}/"
    done
    if [ -d "${NGINX_TXN_BACKUP}/guard" ]; then
        rm -rf "${NGINX_VHOST_DIR}/guard"
        cp -a "${NGINX_TXN_BACKUP}/guard" "${NGINX_VHOST_DIR}/guard"
    else
        rm -rf "${NGINX_VHOST_DIR}/guard"
    fi
    if [ -d "${NGINX_TXN_BACKUP}/rewrite" ]; then
        rm -rf "${PANEL_PATH}/vhost/rewrite"
        cp -a "${NGINX_TXN_BACKUP}/rewrite" "${PANEL_PATH}/vhost/rewrite"
    fi
    if [ -d "${NGINX_TXN_BACKUP}/proxy" ]; then
        rm -rf "${NGINX_VHOST_DIR}/proxy"
        cp -a "${NGINX_TXN_BACKUP}/proxy" "${NGINX_VHOST_DIR}/proxy"
    fi
    if ! grep -qx "0.bt_cpu_guard_http.conf" "${NGINX_TXN_BACKUP}/vhost.manifest" 2>/dev/null; then
        rm -f "${NGINX_VHOST_DIR}/0.bt_cpu_guard_http.conf"
    fi
    log_msg "nginx configuration rolled back"
}

disable_site_total() {
    systemctl stop site_total >/dev/null 2>&1 || true
    systemctl disable site_total >/dev/null 2>&1 || true
    pkill -f "/www/server/site_total/site_total" >/dev/null 2>&1 || true
    mkdir -p /www/server/site_total
    echo "disabled by bt-clean cpu guard" > /www/server/site_total/stop_always.txt
}

setup_logrotate() {
    [ -d /etc/logrotate.d ] || mkdir -p /etc/logrotate.d
    cat > /etc/logrotate.d/nginx_bt_cpu_fix <<'EOF'
/www/wwwlogs/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    dateext
    copytruncate
    maxsize 200M
}
EOF
}

setup_search_spider_ip_verification() {
    updater="${PANEL_PATH}/script/bt_search_spider_ip_update.sh"
    if [ -f "${updater}" ]; then
        chmod 0755 "${updater}"
        /bin/bash "${updater}" --no-reload || true
    fi

    # Keep Nginx valid on partial/manual upgrades where the updater has not
    # been copied yet. Strict fake-spider blocking stays disabled until the
    # official crawler feeds have been fetched successfully.
    spider_state="${PANEL_PATH}/data/bt_search_spider"
    spider_geo="${spider_state}/verified_spider_geo.conf"
    if [ ! -s "${spider_geo}" ]; then
        mkdir -p "${spider_state}"
        cat > "${spider_geo}" <<'EOF'
map $host $bt_clean_spider_ip_data_ready { default 0; }
geo $bt_clean_google_crawler_ip { default 0; }
geo $bt_clean_bing_crawler_ip { default 0; }
geo $bt_clean_baidu_crawler_ip { default 0; }
EOF
    fi
}

setup_conntrack_safeguards() {
    # A full conntrack table drops packets before Nginx sees them. This caused
    # intermittent origin, loopback-upstream, and SSH timeouts under bursts.
    [ -r /proc/sys/net/netfilter/nf_conntrack_max ] || return 0

    mem_kb="$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null)"
    [ -n "${mem_kb}" ] || mem_kb=0
    if [ "${mem_kb}" -ge 16777216 ]; then
        wanted_max=2097152
        wanted_hash=524288
    elif [ "${mem_kb}" -ge 4194304 ]; then
        wanted_max=1048576
        wanted_hash=262144
    else
        wanted_max=262144
        wanted_hash=65536
    fi

    current_max="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
    case "${current_max}" in
        ''|*[!0-9]*) current_max=0 ;;
    esac
    if [ "${current_max}" -gt "${wanted_max}" ]; then
        wanted_max="${current_max}"
    fi

    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/zz-bt-clean-conntrack.conf <<EOF
# bt-clean: high-concurrency Cloudflare origin safeguards.
net.netfilter.nf_conntrack_max = ${wanted_max}
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 30
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 30
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 30
net.netfilter.nf_conntrack_tcp_timeout_close = 10
EOF
    sysctl -p /etc/sysctl.d/zz-bt-clean-conntrack.conf >/dev/null 2>&1 || true

    if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
        current_hash="$(cat /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null)"
        case "${current_hash}" in
            ''|*[!0-9]*) current_hash=0 ;;
        esac
        if [ "${current_hash}" -lt "${wanted_hash}" ]; then
            echo "${wanted_hash}" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
        fi
        mkdir -p /etc/modprobe.d
        echo "options nf_conntrack hashsize=${wanted_hash}" > /etc/modprobe.d/bt-clean-nf-conntrack.conf
    fi

    # The Kuaipai Go deployment uses a loopback-only upstream on 8090. Do not
    # spend public conntrack entries on Nginx-to-local-service connections.
    if command -v iptables >/dev/null 2>&1 && \
       grep -RqsE '127\.0\.0\.1:8090|kuaipai_8090' "${NGINX_VHOST_DIR}" 2>/dev/null && \
       iptables -t raw -j CT --help >/dev/null 2>&1; then
        mkdir -p /usr/local/sbin
        cat > /usr/local/sbin/bt-clean-conntrack-rules.sh <<'EOF'
#!/bin/sh
iptables -t raw -C OUTPUT -o lo -p tcp --dport 8090 -j CT --notrack 2>/dev/null || iptables -t raw -I OUTPUT 1 -o lo -p tcp --dport 8090 -j CT --notrack
iptables -t raw -C OUTPUT -o lo -p tcp --sport 8090 -j CT --notrack 2>/dev/null || iptables -t raw -I OUTPUT 1 -o lo -p tcp --sport 8090 -j CT --notrack
EOF
        chmod 0755 /usr/local/sbin/bt-clean-conntrack-rules.sh
        /usr/local/sbin/bt-clean-conntrack-rules.sh >/dev/null 2>&1 || true
        if command -v systemctl >/dev/null 2>&1; then
            cat > /etc/systemd/system/bt-clean-conntrack.service <<'EOF'
[Unit]
Description=BT Clean high-concurrency conntrack safeguards
After=network-pre.target
Before=bt.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/bt-clean-conntrack-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload >/dev/null 2>&1 || true
            systemctl enable --now bt-clean-conntrack.service >/dev/null 2>&1 || true
        fi
    fi
}

archive_huge_logs() {
    [ "${MODE}" = "--light" ] && return 0
    [ -d "${WWW_LOG_DIR}" ] || return 0
    archive="${WWW_LOG_DIR}/archive_cpu_fix_$(date +%Y%m%d_%H%M%S)"
    moved=0
    find "${WWW_LOG_DIR}" -maxdepth 1 -type f -name "*.log" -size +1024M | while read -r log_file; do
        [ -f "${log_file}" ] || continue
        mkdir -p "${archive}"
        mv "${log_file}" "${archive}/"
        : > "${log_file}"
        moved=1
    done
}

write_nginx_guard() {
    mkdir -p "${NGINX_VHOST_DIR}"
cat > "${NGINX_VHOST_DIR}/0.bt_cpu_guard_http.conf" <<'EOF'
# bt-clean CPU guard: keep common scanners away from PHP and relax search engines.
# Restore the visitor address only when the direct peer is an official Cloudflare proxy.
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;
real_ip_header CF-Connecting-IP;
real_ip_recursive on;

include /www/server/panel/data/bt_search_spider/verified_spider_geo.conf;

variables_hash_max_size 4096;
variables_hash_bucket_size 128;

geo $bt_clean_emergency_bad_ip {
    default 0;
    85.208.96.0/24 1;
    185.191.171.0/24 1;
    216.73.216.0/23 1;
    20.9.0.0/16 1;
    20.104.0.0/16 1;
    20.151.0.0/16 1;
    20.226.88.0/24 1;
    66.132.0.0/16 1;
    136.243.0.0/16 1;
    198.235.24.0/24 1;
}

map $http_user_agent $bt_clean_spider_claim {
    default "";
    "~*(?:Googlebot|Storebot-Google)" google;
    "~*bingbot" bing;
    "~*Baiduspider" baidu;
    "~*(?:Google-InspectionTool|BingPreview|adidxbot|Slurp|DuckDuckBot|Yandex(?:Bot|Images)|Sogou|360Spider|HaosouSpider|Bytespider|PetalBot|Applebot|SemrushBot|AhrefsBot|MJ12bot|DotBot|BLEXBot)" other;
}

map $bt_clean_spider_claim $bt_clean_strict_spider_claim {
    default 0;
    google 1;
    bing 1;
    baidu 1;
}

map "$bt_clean_spider_claim:$bt_clean_google_crawler_ip:$bt_clean_bing_crawler_ip:$bt_clean_baidu_crawler_ip" $bt_clean_search_engine {
    default 0;
    "~^google:1:" 1;
    "~^bing:[01]:1:" 1;
    "~^baidu:[01]:[01]:1$" 1;
}

# Googlebot, Bingbot and Baiduspider are privileged only when both the UA and
# the official crawler network match. When the remote feeds are unavailable on
# first install, fail open for blocking while still applying crawler limits.
map "$bt_clean_strict_spider_claim:$bt_clean_spider_ip_data_ready:$bt_clean_search_engine" $bt_clean_fake_strict_spider {
    default 0;
    "1:1:0" 1;
}

map "$bt_clean_spider_claim:$bt_clean_search_engine" $bt_clean_unverified_spider {
    default 0;
    "~^[^:]+:0$" 1;
}

map "$http_sec_fetch_mode:$http_sec_fetch_dest:$http_accept" $bt_clean_browser_navigation {
    default 0;
    "~^navigate:document:.*(?:text/html|application/xhtml\+xml)" 1;
}

map $http_referer $bt_clean_search_referer {
    default 0;
    "~*(baidu\.com|google\.|bing\.com|sogou\.com|so\.com|haosou\.com|yahoo\.|yandex\.|duckduckgo\.com|sm\.cn|toutiao\.com|shenma\.com)" 1;
}

map "$bt_clean_search_engine:$bt_clean_search_referer:$request_uri" $bt_clean_root_query_probe {
    default 0;
    "~^0:0:/\?.+" 1;
}

map "$bt_clean_search_engine:$bt_clean_search_referer:$request_uri" $bt_clean_random_query_probe {
    default 0;
    "~^0:0:(?:/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]*|/index\.(?:php|html?))\?(?:(?:page|limit)=[0-9]{1,5}|(?:sort|filter)=(?:newest|latest|hot|popular|views|date|time|rand|random)|category=[A-Za-z0-9_-]{1,64}|(?:start_date|end_date)=[0-9]{4}-[0-9]{2}-[0-9]{2})&[A-Za-z0-9]{8,64}(?:=[A-Za-z0-9]{8,64})?(?:&[A-Za-z0-9]{8,64}(?:=[A-Za-z0-9]{8,64})?){0,4}(?:$|&)" 1;
}

# A bare mixed-case token is not a valid application query parameter. This
# signature is deterministic, so a forged search-engine Referer must not bypass it.
map $request_uri $bt_clean_bare_random_query_probe {
    default 0;
    "~^/(?:index\.(?:php|html?))?\?(?=[A-Za-z0-9_-]{6,64}$)(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[a-z])[A-Za-z0-9_-]+$" 1;
}

# Do not let high-rate, unambiguous probes consume disk and log-parser CPU.
map $request_uri $bt_clean_attack_uri_loggable {
    default 1;
    "~^/(?:index\.(?:php|html?))?\?(?=[A-Za-z0-9_-]{6,64}$)(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[a-z])[A-Za-z0-9_-]+$" 0;
    "~*^/\?=[A-Za-z0-9_-]{4,128}(?:&|$)" 0;
    "~*^/(?:Telerik\.Web\.UI\.)?WebResource\.axd\?(?:[^&]*&)*type=rau(?:&|$)" 0;
}

# WAF rejects have their own audit log. Keep them out of site access logs so
# request-stat parsers do not count blocked floods as application traffic.
map "$bt_clean_attack_uri_loggable:$limit_req_status:$status" $bt_clean_attack_loggable {
    default 1;
    "~^0:" 0;
    "~:REJECTED:" 0;
    "~:(?:403|444)$" 0;
}

map $uri $bt_clean_generic_static_asset {
    default 0;
    "~*\.(?:avif|css|eot|gif|ico|jpe?g|js|map|mp3|mp4|ogg|png|svg|webp|woff2?|ttf)$" 1;
}

map "$bt_clean_search_engine:$bt_clean_browser_navigation:$bt_clean_generic_static_asset" $bt_clean_non_search_v3_key {
    default $binary_remote_addr;
    "~^1:" "";
    "~^0:1:" "";
    "0:0:1" "";
}

map $remote_addr $bt_clean_remote_subnet {
    ~^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ $1;
    default $binary_remote_addr;
}

map $bt_clean_unverified_spider $bt_clean_fake_spider_ip_key {
    0 "";
    1 $binary_remote_addr;
}

map $bt_clean_unverified_spider $bt_clean_fake_spider_subnet_key {
    0 "";
    1 $bt_clean_remote_subnet;
}

map $bt_clean_unverified_spider $bt_clean_fake_spider_host_key {
    0 "";
    1 $host;
}

map "$bt_clean_unverified_spider:$request_method" $bt_clean_fake_spider_bad_method {
    default 0;
    "~^1:(?!(?:GET|HEAD)$)" 1;
}

limit_req_zone $bt_clean_fake_spider_ip_key zone=bt_clean_fake_spider_ip:20m rate=2r/s;
limit_req_zone $bt_clean_fake_spider_subnet_key zone=bt_clean_fake_spider_subnet:20m rate=20r/s;
limit_req_zone $bt_clean_fake_spider_host_key zone=bt_clean_fake_spider_host:10m rate=80r/s;

map "$bt_clean_search_engine:$bt_clean_browser_navigation:$bt_clean_generic_static_asset" $bt_clean_non_search_subnet_v3_key {
    default $bt_clean_remote_subnet;
    "~^1:" "";
    "~^0:1:" "";
    "0:0:1" "";
}

map "$request_method:$uri:$bt_clean_browser_navigation:$bt_clean_search_engine" $bt_clean_distributed_landing_key {
    default "";
    "~^(?:GET|HEAD):(?:/|/index\.(?:php|html?)):0:0$" "$host$uri";
}

limit_req_zone $bt_clean_non_search_v3_key zone=bt_clean_non_search_scan_v3:32m rate=4r/s;
limit_req_zone $bt_clean_non_search_subnet_v3_key zone=bt_clean_non_search_subnet_scan_v3:32m rate=40r/s;
limit_req_zone $bt_clean_distributed_landing_key zone=bt_clean_distributed_landing:20m rate=20r/s;

# Compatibility for existing vhosts that used the earlier SpiderPool-specific
# access-log condition. Keep those vhosts valid while applying the generic guard.
map $bt_clean_attack_loggable $spiderpool_attack_loggable {
    default 1;
    0 0;
}

# Compatibility for vhosts created by the earlier global automation limiter.
map $uri $bt_clean_admin_request {
    default 0;
    "~^/(?:admin/spiderpool(?:/|$)|api/admin(?:/|$))" 1;
}

map "$request_method:$bt_clean_search_engine:$bt_clean_admin_request" $bt_clean_automated_global_key {
    default "";
    "~^(?:GET|HEAD):0:0$" $binary_remote_addr;
}

limit_req_zone $bt_clean_automated_global_key zone=bt_clean_automated_global:10m rate=20r/s;
limit_conn_zone $bt_clean_automated_global_key zone=bt_clean_automated_global_conn:10m;
# Compatibility for existing SpiderPool vhosts installed by earlier builds.
# The old hostname key pooled every visitor into one global counter. Use a
# versioned zone because Nginx cannot change an existing zone's key on reload.
limit_conn_zone $binary_remote_addr zone=spiderpool_site_conn_v2:1m;

# /guides/<slug> is a valid SpiderPool route, so never classify it as a bad
# path. Verified search crawlers remain unrestricted. Scope both fallback
# limiters to the real client address: a flood on one domain or address must
# not consume a global token bucket and return 429 to unrelated visitors.
# Distributed rotating-address floods are handled by the aggregate Lua WAF.
map "$request_method:$uri:$bt_clean_browser_navigation:$bt_clean_search_engine" $bt_clean_guide_automation_key {
    default "";
    "~^(?:GET|HEAD):/(?:[a-z][a-z]/)?guides/[A-Za-z0-9%-]+:0:0$" $binary_remote_addr;
}

map "$request_method:$uri:$bt_clean_browser_navigation:$bt_clean_search_engine" $bt_clean_guide_browser_key {
    default "";
    "~^(?:GET|HEAD):/(?:[a-z][a-z]/)?guides/[A-Za-z0-9%-]+:1:0$" $binary_remote_addr;
}

map "$request_method:$uri" $bt_clean_spiderpool_skip_cache {
    default 1;
    "~^(?:GET|HEAD):/$" 0;
    "~^(?:GET|HEAD):/(?:[a-z][a-z]/)?guides/[A-Za-z0-9%-]+$" 0;
}

limit_req_zone $bt_clean_guide_automation_key zone=bt_clean_guide_automation:20m rate=10r/s;
limit_req_zone $bt_clean_guide_browser_key zone=bt_clean_guide_browser:20m rate=30r/s;

# Protect the loopback Kuaipai/Go origin without pooling unrelated visitors.
# Static assets do not consume dynamic-page request or connection buckets.
map $uri $bt_clean_kuaipai_static_asset_v5 {
    default 0;
    "~*\.(?:avif|css|eot|gif|ico|jpe?g|js|map|mp3|mp4|ogg|png|svg|webp|woff2?|ttf)$" 1;
}

map "$binary_remote_addr:$host" $bt_clean_kuaipai_client_host_v5 {
    default "$binary_remote_addr:$host";
}

map "$bt_clean_kuaipai_static_asset_v5:$bt_clean_search_engine:$bt_clean_search_referer:$bt_clean_browser_navigation" $bt_clean_kuaipai_public_key_v5 {
    default $bt_clean_kuaipai_client_host_v5;
    "~^1:" "";
    "~^0:1:" "";
    "0:0:1:1" "";
}

map "$bt_clean_kuaipai_static_asset_v5:$bt_clean_search_engine:$bt_clean_search_referer:$bt_clean_browser_navigation" $bt_clean_kuaipai_search_key_v5 {
    default "";
    "~^0:1:" $bt_clean_kuaipai_client_host_v5;
    "0:0:1:1" $bt_clean_kuaipai_client_host_v5;
}

map $bt_clean_kuaipai_static_asset_v5 $bt_clean_kuaipai_host_key_v5 {
    default $host;
    1 "";
}

map $bt_clean_kuaipai_static_asset_v5 $bt_clean_kuaipai_global_key_v5 {
    default "kuaipai-public-origin-v5";
    1 "";
}

map $bt_clean_kuaipai_static_asset_v5 $bt_clean_kuaipai_client_conn_key_v5 {
    default $bt_clean_kuaipai_client_host_v5;
    1 "";
}

map $request_method $bt_clean_kuaipai_cache_method_skip {
    default 1;
    GET 0;
    HEAD 0;
}

map $uri $bt_clean_kuaipai_cache_path_skip {
    default 0;
    "~^/go-admin(?:/|$)" 1;
    "~^/kuaipai(?:/|$)" 1;
    "~^/healthz$" 1;
    "~^/__status$" 1;
    "~^/login(?:/|$)" 1;
    "~^/go(?:/|$)" 1;
    "~^/icp\.php$" 1;
    "~^/r2-track\.gif$" 1;
    "~^/__kuaipai_visit\.gif$" 1;
    "~^/__kuaipai_redirect_modal\.js$" 1;
}

map $http_authorization $bt_clean_kuaipai_cache_auth_skip {
    default 1;
    "" 0;
}

map $http_cookie $bt_clean_kuaipai_cache_cookie_skip {
    default 1;
    "" 0;
}

map $upstream_http_x_kuaipai_origin_no_store $bt_clean_kuaipai_cache_origin_skip {
    default 1;
    "0" 0;
}

map $upstream_http_cache_control $bt_clean_kuaipai_cache_control_skip {
    default 0;
    "~*(?:no-store|private)" 1;
}

map $upstream_http_set_cookie $bt_clean_kuaipai_cache_set_cookie_skip {
    default 1;
    "" 0;
}

map $upstream_status $bt_clean_kuaipai_cache_status_skip {
    default 1;
    "200" 0;
}

# Compatibility aliases for site files generated by earlier guard releases.
# Keep these until every BaoTa-created vhost has been regenerated; removing
# them can make nginx -t fail while an otherwise valid legacy cache block is
# still active.
map $request_method $bt_clean_kuaipai_cache_method_bypass {
    default 1;
    GET 0;
    HEAD 0;
}

map $uri $bt_clean_kuaipai_cache_uri_bypass {
    default 0;
    "~^/(?:go-admin|kuaipai|healthz|__status|login|go)(?:/|$)" 1;
    "~^/(?:icp\.php|r2-track\.gif|__kuaipai_visit\.gif|__kuaipai_redirect_modal\.js)$" 1;
}

map $upstream_status $bt_clean_kuaipai_status_no_cache {
    default 1;
    "200" 0;
}

map "$upstream_http_x_kuaipai_origin_no_store:$upstream_http_cache_control" $bt_clean_kuaipai_origin_no_cache {
    default 1;
    "~*^0:(?!.*(?:no-store|private))" 0;
}

map $upstream_http_x_kuaipai_rejected_host $bt_clean_kuaipai_rejected_no_cache {
    default 0;
    "~.+" 1;
}

limit_req_zone $bt_clean_kuaipai_public_key_v5 zone=bt_clean_kuaipai_public_v5:32m rate=10r/s;
limit_req_zone $bt_clean_kuaipai_search_key_v5 zone=bt_clean_kuaipai_search_v5:32m rate=30r/s;
limit_req_zone $bt_clean_kuaipai_host_key_v5 zone=bt_clean_kuaipai_host_v5:20m rate=300r/s;
limit_req_zone $bt_clean_kuaipai_global_key_v5 zone=bt_clean_kuaipai_global_v5:10m rate=1500r/s;
limit_conn_zone $bt_clean_kuaipai_client_conn_key_v5 zone=bt_clean_kuaipai_client_conn_v5:20m;
limit_conn_zone $bt_clean_kuaipai_host_key_v5 zone=bt_clean_kuaipai_host_conn_v5:10m;
limit_conn_zone $bt_clean_kuaipai_global_key_v5 zone=bt_clean_kuaipai_global_conn_v5:10m;

proxy_cache_path /www/server/nginx/bt_clean_kuaipai_cache levels=1:2 keys_zone=bt_clean_kuaipai_page_v1:128m inactive=30m max_size=10g use_temp_path=off;

upstream bt_clean_kuaipai_backend {
    zone bt_clean_kuaipai_backend_zone 64k;
    server 127.0.0.1:8090 max_conns=1200;
    keepalive 128;
}

EOF

    # Some panel/WAF versions already provide Cloudflare Real-IP directives in
    # the same http context. Reuse that configuration instead of creating a
    # duplicate real_ip_header directive on every guard refresh.
    if grep -Rsl --include='*.conf' '^[[:space:]]*real_ip_header[[:space:]]' "${NGINX_VHOST_DIR}" 2>/dev/null \
        | grep -Fvx "${NGINX_VHOST_DIR}/0.bt_cpu_guard_http.conf" \
        | grep -q .; then
        sed -i \
            -e '/^[[:space:]]*set_real_ip_from[[:space:]]/d' \
            -e '/^[[:space:]]*real_ip_header[[:space:]]/d' \
            -e '/^[[:space:]]*real_ip_recursive[[:space:]]/d' \
            "${NGINX_VHOST_DIR}/0.bt_cpu_guard_http.conf"
    fi

    # Large verified crawler lists add map variables. Increase the hash only
    # when the administrator has not already chosen values elsewhere.
    if grep -Rsl --include='*.conf' '^[[:space:]]*variables_hash_max_size[[:space:]]' /www/server/nginx/conf "${NGINX_VHOST_DIR}" 2>/dev/null \
        | grep -Fvx "${NGINX_VHOST_DIR}/0.bt_cpu_guard_http.conf" \
        | grep -q .; then
        sed -i \
            -e '/^[[:space:]]*variables_hash_max_size[[:space:]]/d' \
            -e '/^[[:space:]]*variables_hash_bucket_size[[:space:]]/d' \
            "${NGINX_VHOST_DIR}/0.bt_cpu_guard_http.conf"
    fi

    mkdir -p "${NGINX_VHOST_DIR}/guard"
cat > "${NGINX_VHOST_DIR}/guard/bt_cpu_guard_server.conf" <<'EOF'
# bt-clean CPU guard: common automated probes, evaluated before PHP.
access_log /www/wwwlogs/bt_fake_spider.log combined if=$bt_clean_unverified_spider;

if ($bt_clean_fake_strict_spider) {
    return 444;
}

if ($bt_clean_fake_spider_bad_method) {
    return 444;
}

if ($bt_clean_emergency_bad_ip) {
    return 444;
}

# Empty User-Agent floods are not standards-compliant browser traffic. Keep
# curl, wget and python-requests usable when they send their explicit UA.
if ($http_user_agent = "") {
    return 444;
}

if ($bt_clean_root_query_probe) {
    return 444;
}

if ($bt_clean_random_query_probe) {
    return 444;
}

if ($bt_clean_bare_random_query_probe) {
    return 444;
}

# Empty query keys are malformed and commonly used by distributed fake-referrer probes.
if ($request_uri ~* "^/\?=[A-Za-z0-9_-]{4,128}(?:&|$)") {
    return 444;
}

# Telerik RAU is a well-known vulnerable upload-handler probe.
if ($request_uri ~* "^/(?:Telerik\.Web\.UI\.)?WebResource\.axd\?(?:[^&]*&)*type=rau(?:&|$)") {
    return 444;
}

if ($request_uri ~* "^/status(?:\?|/|$)") {
    return 444;
}

if ($request_uri ~* "^/css\.php(?:\?xj(?:/|=|$)|/xj(?:/|$))") {
    return 444;
}

if ($request_uri ~* "^/status\?.*(appkey|bundleid|idfa|device|sdkver|jailbreak|clickeffects)=") {
    return 444;
}

location ~* "(^|/)(\.env(\.|$)|\.git/|\.svn/|wp-(admin|login|config|content|includes)|xmlrpc\.php|composer\.(json|lock)|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|\.DS_Store|id_rsa|authorized_keys|phpinfo\.php)$" {
    access_log off;
    return 444;
}

if ($request_uri ~* "(base64_decode|eval\(|assert\(|pboot|/e/admin|/dede|/plus/|/wp-json/wp/v2/users|/index\.php\?s=/|/\.well-known/.*\.\.)") {
    return 444;
}

if ($request_uri ~* "^/(wp-[^/]*|[a-z0-9_-]{2,16}\.php|admin\.php|sg\.php|hur\.php|puc\.php|mac\.php|mixer-en\.php|ioxi-o\.php|wp-kz\.php)$") {
    return 444;
}

limit_req_status 429;
limit_req_log_level notice;
limit_conn_status 429;
limit_conn_log_level notice;

limit_req zone=bt_clean_fake_spider_ip burst=6 nodelay;
limit_req zone=bt_clean_fake_spider_subnet burst=30 nodelay;
limit_req zone=bt_clean_fake_spider_host burst=120 nodelay;
limit_req zone=bt_clean_distributed_landing burst=60 nodelay;
    limit_req zone=bt_clean_non_search_scan_v3 burst=12 nodelay;
    limit_req zone=bt_clean_non_search_subnet_scan_v3 burst=60 nodelay;
EOF
}

patch_nginx_vhosts() {
    [ -d "${NGINX_VHOST_DIR}" ] || return 0
    for conf in "${NGINX_VHOST_DIR}"/*.conf; do
        [ -f "${conf}" ] || continue
        case "$(basename "${conf}")" in
            0.bt_cpu_guard_http.conf|bt_cpu_guard_server.conf|phpfpm_status.conf|0.websocket.conf)
                continue
                ;;
        esac
        # Releases before 2026-08-13 used a second server include with
        # limit_req_status 444. Cloudflare represents that empty response as
        # a 520 page, so remove the obsolete include during every upgrade.
        sed -i '\#/www/server/panel/vhost/nginx/guard/bt_cpu_guard_spiderpool\.conf#d' "${conf}"
        # The shared server guard owns limit status and log-level directives.
        # Remove historical per-site copies to avoid duplicate directives when
        # a site also includes SpiderPool or cache-specific configuration.
        sed -i -E '/^[[:space:]]*limit_(req|conn)_(status|log_level)[[:space:]]+/d' "${conf}"
        # Drop site-level references to retired Kuaipai zones. Their keys were
        # shared across visitors and the declarations are intentionally absent
        # from the v5 http guard; leaving one reference makes nginx -t fail.
        sed -i -E \
            -e '/^[[:space:]]*limit_req[[:space:]]+zone=bt_clean_kuaipai_.*_v[0-4][[:space:]]/d' \
            -e '/^[[:space:]]*limit_conn[[:space:]]+bt_clean_kuaipai_.*_v[0-4][[:space:]]/d' \
            "${conf}"
        if grep -q "/www/server/panel/vhost/nginx/bt_cpu_guard_server.conf" "${conf}"; then
            sed -i "s#/www/server/panel/vhost/nginx/bt_cpu_guard_server.conf#/www/server/panel/vhost/nginx/guard/bt_cpu_guard_server.conf#g" "${conf}"
        fi
        grep -q "/www/server/panel/vhost/nginx/guard/bt_cpu_guard_server.conf" "${conf}" && continue
        awk 'BEGIN{done=0} {print; if(!done && $0 ~ /^[[:space:]]*server_name[[:space:]]+/){print "    include /www/server/panel/vhost/nginx/guard/bt_cpu_guard_server.conf;"; done=1}}' "${conf}" > "${conf}.cpu_guard.tmp" && mv "${conf}.cpu_guard.tmp" "${conf}"
    done
}

patch_spiderpool_vhosts() {
    [ -d "${NGINX_VHOST_DIR}" ] || return 0
    for conf in "${NGINX_VHOST_DIR}"/*.conf; do
        [ -f "${conf}" ] || continue
        case "$(basename "${conf}")" in
            0.bt_cpu_guard_http.conf|bt_cpu_guard_server.conf|phpfpm_status.conf|0.websocket.conf)
                continue
                ;;
        esac

        site_name="$(basename "${conf}" .conf)"
        proxy_dir="${NGINX_VHOST_DIR}/proxy/${site_name}"
        if ! grep -qsE '127\.0\.0\.1:18990|localhost:18990' "${conf}" && \
           ! grep -RqsE '127\.0\.0\.1:18990|localhost:18990' "${proxy_dir}" 2>/dev/null; then
            continue
        fi

        # Remove obsolete blocks and normalize the shared-origin protection.
        awk '
            /# bt-clean-spiderpool-guides-flood-start/ { skip=1; next }
            /# bt-clean-spiderpool-guides-flood-end/ { skip=0; next }
            /# bt-clean-spiderpool-global-flood-start/ { skip=1; next }
            /# bt-clean-spiderpool-global-flood-end/ { skip=0; next }
            !skip { print }
        ' "${conf}" > "${conf}.spiderpool.tmp"

        mv "${conf}.spiderpool.tmp" "${conf}"
        sed -i -E \
            -e '/^[[:space:]]*limit_conn[[:space:]]+spiderpool_site_conn(_v2)?[[:space:]]+/d' \
            -e '/^[[:space:]]*limit_(req|conn)_(status|log_level)[[:space:]]+/d' \
            "${conf}"
        awk '
            BEGIN { done=0 }
            {
                print
                if (!done && $0 ~ /^[[:space:]]*server_name[[:space:]]+/) {
                    print "    # bt-clean-spiderpool-guides-flood-start"
                    print "    limit_req zone=bt_clean_guide_automation burst=20 nodelay;"
                    print "    limit_req zone=bt_clean_guide_browser burst=60 nodelay;"
                    print "    limit_conn spiderpool_site_conn_v2 12;"
                    print "    # bt-clean-spiderpool-guides-flood-end"
                    done=1
                }
            }
        ' "${conf}" > "${conf}.spiderpool.tmp" && mv "${conf}.spiderpool.tmp" "${conf}"
    done

    ensure_kuaipai_cache_zone
    pybin=""
    if command -v python3 >/dev/null 2>&1; then
        pybin="$(command -v python3)"
    elif [ -x /www/server/panel/pyenv/bin/python ]; then
        pybin="/www/server/panel/pyenv/bin/python"
    fi
    if [ -n "${pybin}" ]; then
        "${pybin}" - <<'PY'
from pathlib import Path
import re

root = Path('/www/server/panel/vhost/nginx/proxy')
cache = '''
    # bt-clean-spiderpool-public-cache-start
    proxy_cache cache_one;
    proxy_cache_key "$scheme$request_method$host$request_uri";
    proxy_cache_methods GET HEAD;
    proxy_cache_valid 200 10m;
    proxy_cache_valid 301 302 10m;
    proxy_cache_min_uses 1;
    proxy_cache_lock on;
    proxy_cache_lock_timeout 8s;
    proxy_cache_lock_age 8s;
    proxy_cache_background_update on;
    proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
    proxy_cache_bypass $bt_clean_spiderpool_skip_cache $http_authorization;
    proxy_no_cache $bt_clean_spiderpool_skip_cache $http_authorization $upstream_http_set_cookie;
    add_header X-Cache $upstream_cache_status always;
    # bt-clean-spiderpool-public-cache-end
'''

for path in root.rglob('*.conf') if root.exists() else []:
    original = path.read_text(encoding='utf-8', errors='ignore')
    if not re.search(r'proxy_pass\s+http://(?:127\.0\.0\.1|localhost):18990\s*;', original):
        continue
    text = re.sub(
        r'\n?[ \t]*# bt-clean-spiderpool-public-cache-start.*?# bt-clean-spiderpool-public-cache-end[ \t]*\n?',
        '\n', original, flags=re.S,
    )
    text = re.sub(r'^[ \t]*proxy_cache\s+off\s*;[ \t]*\n', '', text, flags=re.M)
    if not re.search(r'^\s*proxy_cache\s+cache_one\s*;', text, flags=re.M):
        text = re.sub(
            r'(proxy_pass\s+http://(?:127\.0\.0\.1|localhost):18990\s*;)',
            r'\1' + cache, text, count=1,
        )
    elif '$bt_clean_spiderpool_skip_cache' not in text:
        text = re.sub(
            r'(^\s*proxy_cache\s+cache_one\s*;)',
            r'\1\n    proxy_cache_bypass $bt_clean_spiderpool_skip_cache $http_authorization;\n    proxy_no_cache $bt_clean_spiderpool_skip_cache $http_authorization $upstream_http_set_cookie;',
            text, count=1, flags=re.M,
        )
    if text != original:
        backup = path.with_name(path.name + '.bt-clean-before-spiderpool-cache')
        if not backup.exists():
            backup.write_text(original, encoding='utf-8')
        path.write_text(text, encoding='utf-8')
        print(f'patched {path}')
PY
    fi

    # Nothing should include this compatibility file after the migration.
    rm -f "${NGINX_VHOST_DIR}/guard/bt_cpu_guard_spiderpool.conf"
    # A short-lived emergency release wrote this http-context zone into a
    # separate file. The managed zone above supersedes it and avoids duplicate
    # map/zone declarations on upgraded hosts.
    rm -f "${NGINX_VHOST_DIR}/1.spiderpool_global_flood.conf"
}

ensure_kuaipai_cache_zone() {
    proxy_conf="/www/server/nginx/conf/proxy.conf"
    [ -f "${proxy_conf}" ] || return 0
    grep -Rqs --include='*.conf' 'keys_zone=cache_one:' /www/server/nginx/conf && return 0
    cp -a "${proxy_conf}" "${proxy_conf}.bt-clean-before-cache"
    printf '%s\n' 'proxy_cache_path /www/server/nginx/proxy_cache_dir levels=1:2 keys_zone=cache_one:20m inactive=1d max_size=1g;' >> "${proxy_conf}"
}

patch_kuaipai_go_proxies() {
    pybin=""
    if command -v python3 >/dev/null 2>&1; then
        pybin="$(command -v python3)"
    elif [ -x /www/server/panel/pyenv/bin/python ]; then
        pybin="/www/server/panel/pyenv/bin/python"
    fi
    [ -n "${pybin}" ] || return 0
    mkdir -p /www/server/nginx/bt_clean_kuaipai_cache

    "${pybin}" - <<'PY'
from pathlib import Path
import re

roots = [
    Path('/www/server/panel/vhost/rewrite'),
    Path('/www/server/panel/vhost/nginx/proxy'),
]

guard = '''    # CODEX-PUBLIC-GO-FLOOD-GUARD-START
    limit_req zone=bt_clean_kuaipai_public_v5 burst=30 nodelay;
    limit_req zone=bt_clean_kuaipai_search_v5 burst=100 nodelay;
    limit_req zone=bt_clean_kuaipai_host_v5 burst=600 nodelay;
    limit_req zone=bt_clean_kuaipai_global_v5 burst=3000 nodelay;
    limit_conn bt_clean_kuaipai_client_conn_v5 80;
    limit_conn bt_clean_kuaipai_host_conn_v5 1200;
    limit_conn bt_clean_kuaipai_global_conn_v5 10000;
    proxy_connect_timeout 3s;
    proxy_send_timeout 30s;
    proxy_read_timeout 20s;
    # CODEX-PUBLIC-GO-FLOOD-GUARD-END
'''

cache = '''
        # CODEX-PUBLIC-MICROCACHE-START
        proxy_cache bt_clean_kuaipai_page_v1;
        proxy_cache_methods GET HEAD;
        proxy_cache_key "$scheme$host$request_uri";
        proxy_cache_valid 200 5m;
        proxy_cache_lock on;
        proxy_cache_lock_timeout 8s;
        proxy_cache_lock_age 8s;
        proxy_cache_revalidate on;
        proxy_cache_background_update on;
        proxy_cache_use_stale error timeout updating http_429 http_500 http_502 http_503 http_504;
        proxy_cache_bypass $bt_clean_kuaipai_cache_method_skip $bt_clean_kuaipai_cache_path_skip $bt_clean_kuaipai_cache_auth_skip $bt_clean_kuaipai_cache_cookie_skip;
        proxy_no_cache $bt_clean_kuaipai_cache_method_skip $bt_clean_kuaipai_cache_path_skip $bt_clean_kuaipai_cache_auth_skip $bt_clean_kuaipai_cache_cookie_skip $bt_clean_kuaipai_cache_origin_skip $bt_clean_kuaipai_cache_control_skip $bt_clean_kuaipai_cache_set_cookie_skip $bt_clean_kuaipai_cache_status_skip $upstream_http_x_kuaipai_rejected_host;
        proxy_ignore_headers Cache-Control Expires;
        add_header X-Kuaipai-Origin-Cache $upstream_cache_status always;
        # CODEX-PUBLIC-MICROCACHE-END'''

def remove_block(text, start, end):
    return re.sub(r'(?ms)^\s*# ' + re.escape(start) + r'.*?^\s*# ' + re.escape(end) + r'\s*\n?', '', text)

for root in roots:
    if not root.exists():
        continue
    for path in root.rglob('*.conf'):
        lowered = str(path).lower()
        if '.bak' in lowered or 'before-' in lowered or 'admin' in path.name.lower():
            continue
        if root.name == 'proxy':
            relative = path.relative_to(root)
            site_name = relative.parts[0] if len(relative.parts) > 1 else ''
            rewrite_path = Path('/www/server/panel/vhost/rewrite') / (site_name + '.conf')
            vhost_path = Path('/www/server/panel/vhost/nginx') / (site_name + '.conf')
            if site_name and vhost_path.exists():
                try:
                    vhost_text = vhost_path.read_text(encoding='utf-8')
                except (OSError, UnicodeError):
                    vhost_text = ''
                if 'bt_clean_kuaipai_public_v5' in vhost_text or 'CODEX-PUBLIC-GO-FLOOD-GUARD-START' in vhost_text:
                    continue
            if site_name and rewrite_path.exists():
                try:
                    rewrite_text = rewrite_path.read_text(encoding='utf-8')
                except (OSError, UnicodeError):
                    rewrite_text = ''
                if re.search(r'(?:127\.0\.0\.1:8090|kuaipai_8090|bt_clean_kuaipai_backend)', rewrite_text):
                    continue
        try:
            original = path.read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            continue
        if root.name == 'proxy' and (
            'CODEX-ADMIN-GUARD-START' in original
            or 'CODEX-KUAIPAI-FLOOD-GUARD-START' in original
        ):
            continue
        if not re.search(r'(?:127\.0\.0\.1:8090|kuaipai_8090|bt_clean_kuaipai_backend)', original):
            continue

        text = remove_block(original, 'CODEX-PUBLIC-GO-FLOOD-GUARD-START', 'CODEX-PUBLIC-GO-FLOOD-GUARD-END')
        text = remove_block(text, 'CODEX-PUBLIC-MICROCACHE-START', 'CODEX-PUBLIC-MICROCACHE-END')

        # Harden legacy cache blocks in place. Older panel templates omitted
        # Cookie/path/upstream policy checks and can otherwise cache private
        # responses even though their cache layout is still syntactically valid.
        if re.search(r'^\s*proxy_cache\s+', text, flags=re.M):
            bypass_terms = (
                '$bt_clean_kuaipai_cache_method_skip',
                '$bt_clean_kuaipai_cache_path_skip',
                '$bt_clean_kuaipai_cache_auth_skip',
                '$bt_clean_kuaipai_cache_cookie_skip',
            )
            no_cache_terms = bypass_terms + (
                '$bt_clean_kuaipai_cache_origin_skip',
                '$bt_clean_kuaipai_cache_control_skip',
                '$bt_clean_kuaipai_cache_set_cookie_skip',
                '$bt_clean_kuaipai_cache_status_skip',
                '$upstream_http_x_kuaipai_rejected_host',
            )

            def extend_directive(match, terms):
                value = match.group(1).strip()
                for term in terms:
                    if term not in value:
                        value += ' ' + term
                return match.group(0).split(None, 1)[0] + ' ' + value + ';'

            text = re.sub(
                r'^\s*proxy_cache_bypass\s+([^;]+);',
                lambda match: extend_directive(match, bypass_terms),
                text,
                flags=re.M,
            )
            text = re.sub(
                r'^\s*proxy_no_cache\s+([^;]+);',
                lambda match: extend_directive(match, no_cache_terms),
                text,
                flags=re.M,
            )
        text = re.sub(
            r'proxy_pass\s+http://(?:127\.0\.0\.1:8090|kuaipai_8090)(/?)\s*;',
            lambda match: 'proxy_pass http://bt_clean_kuaipai_backend' + match.group(1) + ';',
            text,
        )

        # Preserve unmarked site directives during upgrades.

        lines = text.splitlines(keepends=True)
        target = next((i for i, line in enumerate(lines) if 'proxy_pass http://bt_clean_kuaipai_backend;' in line), None)
        if target is None:
            target = next((i for i, line in enumerate(lines) if 'proxy_pass http://bt_clean_kuaipai_backend/;' in line), None)
        if target is None:
            continue
        if root.name == 'rewrite':
            lines.insert(0, guard)
        else:
            depth = 0
            location_line = None
            for i in range(target, -1, -1):
                depth += lines[i].count('}') - lines[i].count('{')
                if depth < 0 and re.search(r'^\s*location\s+[^;]+(?:\{|$)', lines[i]):
                    location_line = i
                    break
            if location_line is None:
                continue
            indent = re.match(r'^(\s*)', lines[location_line]).group(1)
            block = ''.join(indent + part.lstrip() if part.strip() else part for part in guard.splitlines(keepends=True))
            opening_line = location_line
            if '{' not in lines[location_line] and location_line + 1 < len(lines) and '{' in lines[location_line + 1]:
                opening_line = location_line + 1
            lines.insert(opening_line + 1, block)
        text = ''.join(lines)

        if root.name == 'rewrite' and not re.search(r'^\s*proxy_cache(?:_[a-z_]+)?\s+', text, flags=re.M):
            text = text.replace('proxy_pass http://bt_clean_kuaipai_backend;', 'proxy_pass http://bt_clean_kuaipai_backend;' + cache, 1)

        if text != original:
            backup = path.with_name(path.name + '.bt-clean-before-go-guard')
            if not backup.exists():
                backup.write_text(original, encoding='utf-8')
            path.write_text(text, encoding='utf-8')
            print(f'patched {path}')
PY
}

tune_kuaipai_service() {
    command -v systemctl >/dev/null 2>&1 || return 0
    systemctl cat kuaipai-go.service >/dev/null 2>&1 || return 0
    mkdir -p /etc/systemd/system/kuaipai-go.service.d
    cat > /etc/systemd/system/kuaipai-go.service.d/bt-clean-limits.conf <<'EOF'
[Service]
CPUQuota=2000%
MemoryMax=16G
TasksMax=2048
LimitNOFILE=200000
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ "${MODE}" != "--light" ]; then
        systemctl restart kuaipai-go.service >/dev/null 2>&1 || true
    fi
}

tune_spiderpool_service() {
    command -v systemctl >/dev/null 2>&1 || return 0
    systemctl cat spiderpool.service >/dev/null 2>&1 || return 0
    mkdir -p /etc/systemd/system/spiderpool.service.d
    cat > /etc/systemd/system/spiderpool.service.d/zzz-btclean-automation.conf <<'EOF'
[Service]
CPUQuota=1600%
MemoryMax=8G
Environment=GOMEMLIMIT=6GiB
Environment=GOGC=75
Environment=GOMAXPROCS=16
Environment=SPIDERPOOL_RENDER_GUARD_ENABLED=true
Environment=SPIDERPOOL_RENDER_MAX_CONCURRENCY=64
Environment=SPIDERPOOL_RENDER_LOAD1_LIMIT=64
Environment=SPIDERPOOL_RENDER_LOAD_SHED_MIN_INFLIGHT=64
Environment=SPIDERPOOL_RENDER_CIRCUIT_BREAK_SECONDS=0
Environment=SPIDERPOOL_RENDER_OVERLOAD_RETRY_SECONDS=1
Environment=SPIDERPOOL_REQUEST_TRACK_BUFFER_MB=128
Environment=SPIDERPOOL_REQUEST_TRACK_FLUSH_COUNT=10000
Environment=SPIDERPOOL_REQUEST_TRACK_FLUSH_MS=5000
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ "${MODE}" != "--light" ]; then
        systemctl restart spiderpool.service >/dev/null 2>&1 || true
    fi
}

patch_attack_log_filter() {
    [ -d "${NGINX_VHOST_DIR}" ] || return 0
    for conf in "${NGINX_VHOST_DIR}"/*.conf; do
        [ -f "${conf}" ] || continue
        case "$(basename "${conf}")" in
            0.bt_cpu_guard_http.conf|bt_cpu_guard_server.conf|phpfpm_status.conf|0.websocket.conf)
                continue
                ;;
        esac
        awk '
            /^[[:space:]]*access_log[[:space:]]+off[[:space:]]*;/ { print; next }
            /^[[:space:]]*access_log[[:space:]]+/ {
                if ($0 !~ /if=/ && $0 !~ /\$bt_clean_attack_loggable/) {
                    probe=$0
                    sub(/^[[:space:]]*/, "", probe)
                    sub(/[[:space:]]*;[[:space:]]*$/, "", probe)
                    fields=split(probe, parts, /[[:space:]]+/)
                    if (fields == 2) {
                        sub(/[[:space:]]*;[[:space:]]*$/, " combined if=$bt_clean_attack_loggable;")
                    } else {
                        sub(/[[:space:]]*;[[:space:]]*$/, " if=$bt_clean_attack_loggable;")
                    }
                }
            }
            { print }
        ' "${conf}" > "${conf}.cpu_guard_log.tmp" && mv "${conf}.cpu_guard_log.tmp" "${conf}"
    done
}

set_fpm_value() {
    conf="$1"
    key="$2"
    value="$3"
    if grep -qE "^[;[:space:]]*${key}[[:space:]]*=" "${conf}"; then
        sed -i "s#^[;[:space:]]*${key}[[:space:]]*=.*#${key} = ${value}#g" "${conf}"
        awk -v k="${key}" 'BEGIN{seen=0} $0 ~ "^[;[:space:]]*" k "[[:space:]]*=" {seen++; if(seen>1) next} {print}' "${conf}" > "${conf}.dedup" && mv "${conf}.dedup" "${conf}"
    else
        echo "${key} = ${value}" >> "${conf}"
    fi
}

patch_php_fpm() {
    for conf in /www/server/php/*/etc/php-fpm.conf; do
        [ -f "${conf}" ] || continue
        phpv="$(echo "${conf}" | awk -F/ '{print $(NF-2)}')"
        before="$(md5sum "${conf}" 2>/dev/null | awk '{print $1}')"
        if grep -qE "^[[:space:]]*pm[[:space:]]*=" "${conf}"; then
            sed -i "s/^[[:space:]]*pm[[:space:]]*=.*/pm = dynamic/g" "${conf}"
        else
            echo "pm = dynamic" >> "${conf}"
        fi
        set_fpm_value "${conf}" "pm.max_children" "80"
        set_fpm_value "${conf}" "pm.start_servers" "6"
        set_fpm_value "${conf}" "pm.min_spare_servers" "3"
        set_fpm_value "${conf}" "pm.max_spare_servers" "20"
        set_fpm_value "${conf}" "pm.max_requests" "300"
        set_fpm_value "${conf}" "request_terminate_timeout" "15"
        if grep -qE "^[;[:space:]]*request_slowlog_timeout[[:space:]]*=" "${conf}"; then
            set_fpm_value "${conf}" "request_slowlog_timeout" "10"
            mkdir -p "/www/server/php/${phpv}/var/log"
            set_fpm_value "${conf}" "slowlog" "/www/server/php/${phpv}/var/log/slow.log"
        fi
        after="$(md5sum "${conf}" 2>/dev/null | awk '{print $1}')"
        if [ -n "${before}" ] && [ "${before}" != "${after}" ]; then
            if [ -x "/etc/init.d/php-fpm-${phpv}" ]; then
                /etc/init.d/php-fpm-${phpv} reload >/dev/null 2>&1 || /etc/init.d/php-fpm-${phpv} restart >/dev/null 2>&1 || true
            fi
        fi
    done
}

reload_nginx_if_valid() {
    nginx_bin=""
    nginx_args=""
    if [ -x /www/server/nginx/sbin/nginx.real_btclean ]; then
        nginx_bin="/www/server/nginx/sbin/nginx.real_btclean"
        nginx_args="-p /www/server/nginx/ -c /www/server/nginx/conf/nginx.conf"
    elif [ -x /www/server/nginx/sbin/nginx ]; then
        nginx_bin="/www/server/nginx/sbin/nginx"
    elif command -v nginx >/dev/null 2>&1; then
        nginx_bin="$(command -v nginx)"
    fi
    if [ -n "${nginx_bin}" ]; then
        if "${nginx_bin}" ${nginx_args} -t; then
            if [ -n "${nginx_args}" ]; then
                "${nginx_bin}" ${nginx_args} -s reload
            elif [ -x /etc/init.d/nginx ]; then
                /etc/init.d/nginx reload >/dev/null 2>&1
            else
                "${nginx_bin}" -s reload
            fi
            return $?
        fi
        rollback_nginx_transaction
        "${nginx_bin}" ${nginx_args} -t || return 1
        if [ -n "${nginx_args}" ]; then
            "${nginx_bin}" ${nginx_args} -s reload
        elif [ -x /etc/init.d/nginx ]; then
            /etc/init.d/nginx reload >/dev/null 2>&1
        else
            "${nginx_bin}" -s reload
        fi
        return 1
    fi
}

install_darkjump_path_guard() {
    command -v systemctl >/dev/null 2>&1 || return 0

    cat > /usr/local/sbin/bt-clean-darkjump-guard <<'GUARD'
#!/bin/bash
set -u

proxy_conf="/www/server/nginx/conf/proxy.conf"
payload="/www/server/nginx/html/waf.lua"
nginx_bin="/www/server/nginx/sbin/nginx.real_btclean"
nginx_prefix="/www/server/nginx/"
nginx_conf="/www/server/nginx/conf/nginx.conf"
changed=0

exec 9>/run/lock/bt-clean-darkjump-guard.lock
flock -n 9 || exit 0

if [ -f "$proxy_conf" ] && grep -qE '^[[:space:]]*(lua_shared_dict[[:space:]]+my_cache[[:space:]]+10m|(access|body_filter|header_filter)_by_lua_file[[:space:]]+/www/server/nginx/html/waf\.lua);[[:space:]]*$' "$proxy_conf"; then
    chattr -i -a "$proxy_conf" 2>/dev/null || true
    tmp="$(mktemp "${proxy_conf}.clean.XXXXXX")"
    sed -E \
        -e '\#^[[:space:]]*lua_shared_dict[[:space:]]+my_cache[[:space:]]+10m;[[:space:]]*$#d' \
        -e '\#^[[:space:]]*(access|body_filter|header_filter)_by_lua_file[[:space:]]+/www/server/nginx/html/waf\.lua;[[:space:]]*$#d' \
        "$proxy_conf" >"$tmp"
    chmod --reference="$proxy_conf" "$tmp"
    chown --reference="$proxy_conf" "$tmp"
    mv -f "$tmp" "$proxy_conf"
    changed=1
fi

if [ -e "$payload" ]; then
    hash="$(sha256sum "$payload" 2>/dev/null | awk '{print $1}')"
    logger -t bt-clean-darkjump-guard "removing legacy redirect payload sha256=${hash:-unknown}"
    chattr -i -a "$payload" 2>/dev/null || true
    shred -u "$payload" 2>/dev/null || rm -f "$payload"
    changed=1
fi

if [ "$changed" -eq 1 ]; then
    sleep 1
    if "$nginx_bin" -t -p "$nginx_prefix" -c "$nginx_conf"; then
        "$nginx_bin" -p "$nginx_prefix" -c "$nginx_conf" -s reload
        logger -t bt-clean-darkjump-guard "legacy redirect entry removed; nginx reloaded"
    else
        logger -t bt-clean-darkjump-guard "legacy redirect removed but nginx config still invalid"
        exit 1
    fi
fi
GUARD
    chmod 0700 /usr/local/sbin/bt-clean-darkjump-guard

    cat > /etc/systemd/system/bt-clean-darkjump-guard.service <<'EOF'
[Unit]
Description=Remove known legacy Nginx mobile redirect backdoor
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/bt-clean-darkjump-guard
EOF

    cat > /etc/systemd/system/bt-clean-darkjump-guard.path <<'EOF'
[Unit]
Description=Watch for known legacy Nginx mobile redirect backdoor

[Path]
PathChanged=/www/server/nginx/conf/proxy.conf
PathExists=/www/server/nginx/html/waf.lua
Unit=bt-clean-darkjump-guard.service

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable --now bt-clean-darkjump-guard.path >/dev/null 2>&1 || true
}

install_cron() {
    command -v crontab >/dev/null 2>&1 || return 0
    (crontab -l 2>/dev/null | grep -v "bt_cpu_guard.sh" | grep -v "bt_search_spider_ip_update.sh"; \
        echo "*/10 * * * * /bin/bash /www/server/panel/script/bt_cpu_guard.sh --light >/dev/null 2>&1"; \
        echo "17 3 * * * /bin/bash /www/server/panel/script/bt_search_spider_ip_update.sh >/dev/null 2>&1") | crontab - >/dev/null 2>&1
}


# BT-CLEAN-READONLY-PERIODIC-V1
# Scheduled checks must not rewrite site configuration or restart services.
exec 8>/run/lock/bt-cpu-guard-maintenance.lock
flock -n 8 || exit 0
if [ "$MODE" = "--light" ]; then
    check_nginx=/www/server/nginx/sbin/nginx.real_btclean
    [ -x "$check_nginx" ] || check_nginx=/www/server/nginx/sbin/nginx
    if "$check_nginx" -p /www/server/nginx/ -c /www/server/nginx/conf/nginx.conf -t; then
        exit 0
    fi
    logger -t bt-cpu-guard 'Nginx validation failed; running workers and site files left unchanged'
    exit 1
fi

quarantine_usbnotify_persistence
quarantine_known_mobile_redirect_backdoor
purge_known_darkjump_artifacts
disable_site_total
setup_logrotate
setup_search_spider_ip_verification
setup_conntrack_safeguards
archive_huge_logs
begin_nginx_transaction
write_nginx_guard
patch_nginx_vhosts
patch_spiderpool_vhosts
patch_kuaipai_go_proxies
patch_attack_log_filter
rm -f "${NGINX_VHOST_DIR}/bt_cpu_guard_server.conf"
patch_php_fpm
if ! reload_nginx_if_valid; then
    log_msg "nginx update failed; previous configuration restored"
    exit 1
fi
tune_kuaipai_service
tune_spiderpool_service
install_darkjump_path_guard
install_cron
log_msg "done"
