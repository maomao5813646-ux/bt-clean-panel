#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-install}"
NGINX_CONF="/www/server/nginx/conf/nginx.conf"
NGINX_BIN="/www/server/nginx/sbin/nginx"
WAF_DIR="/www/server/nginx/conf/local_waf"
PLUGIN_DIR="/www/server/panel/plugin/local_waf"
INCLUDE_LINE="    include /www/server/nginx/conf/local_waf/local_waf.conf;"

install_lua_json() {
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y lua-cjson >/dev/null 2>&1 || \
      (DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y lua-cjson >/dev/null 2>&1) || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y lua-cjson >/dev/null 2>&1 || true
  fi
}

write_files() {
  mkdir -p "$WAF_DIR" "$PLUGIN_DIR"
  [ -f "$WAF_DIR/install.time" ] || date +%s > "$WAF_DIR/install.time"
  cat > "$WAF_DIR/local_waf.conf" <<'EOF'
lua_shared_dict local_waf_cache 20m;
access_by_lua_file /www/server/nginx/conf/local_waf/waf.lua;
EOF
  if [ ! -f "$WAF_DIR/config.json" ]; then
    cat > "$WAF_DIR/config.json" <<'EOF'
{
  "enabled": true,
  "response_code": 403,
  "cc_window": 10,
  "cc_limit": 60,
  "distributed_window": 5,
  "distributed_limit": 120,
  "scan_window": 10,
  "scan_limit": 6,
  "scan_block_time": 60,
  "automation_window": 10,
  "automation_limit": 120,
  "automation_distinct_limit": 24,
  "automation_distributed_limit": 80,
  "automation_distributed_ip_limit": 12,
  "automation_block_time": 300,
  "features": {
    "cc": true,
    "sql": true,
    "xss": true,
    "command": true,
    "weak_password": true,
    "sensitive_path": true,
    "php_code": true,
    "upload": true,
    "bad_ua": true,
    "method_filter": true,
    "block_foreign": false,
    "block_china": false,
    "custom": true,
    "automation": true
  },
  "region": {
    "enabled": false,
    "mode": "block",
    "countries": [],
    "sites": []
  },
  "spiders": {
    "google": "verify",
    "bing": "verify",
    "baidu": "verify",
    "sogou": "allow",
    "360": "allow",
    "shenma": "allow",
    "duckduckgo": "allow",
    "yandex": "allow",
    "apple": "allow",
    "bytespider": "allow",
    "petal": "allow",
    "yahoo": "allow",
    "seo_tools": "block",
    "other": "allow"
  },
  "lists": {
    "ip_whitelist": ["127.0.0.1", "::1"],
    "ip_blacklist": [],
    "ua_whitelist": [],
    "ua_blacklist": [],
    "url_whitelist": [],
    "url_blacklist": [],
    "method_blacklist": ["TRACE"],
    "custom_rules": []
  }
}
EOF
  fi
  touch "$WAF_DIR/waf.log"
  chmod 666 "$WAF_DIR/waf.log"
  cat > /etc/logrotate.d/bt-local-waf <<'EOF'
/www/server/nginx/conf/local_waf/waf.log {
    daily
    size 50M
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
EOF
  cat > /etc/cron.d/bt-local-waf-logrotate <<'EOF'
*/10 * * * * root /usr/sbin/logrotate /etc/logrotate.d/bt-local-waf >/dev/null 2>&1
EOF
  chmod 644 /etc/cron.d/bt-local-waf-logrotate
  cat > "$WAF_DIR/waf.lua" <<'EOF'
local bt_waf_cpath_suffix = ";/usr/lib/x86_64-linux-gnu/lua/5.1/?.so;/usr/lib64/lua/5.1/?.so;/usr/local/lib/lua/5.1/?.so;/usr/lib/lua/5.1/?.so"
if not string.find(package.cpath, bt_waf_cpath_suffix, 1, true) then
    package.cpath = package.cpath .. bt_waf_cpath_suffix
end
local ok_cjson, cjson = pcall(require, "cjson.safe")
if not ok_cjson then
    ok_cjson, cjson = pcall(require, "cjson")
end
if not ok_cjson or not cjson then
    ngx.log(ngx.ERR, "local_waf disabled: lua-cjson module not found")
    return
end
local config_file = "/www/server/nginx/conf/local_waf/config.json"
local log_file = "/www/server/nginx/conf/local_waf/waf.log"

local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    return data
end

local function load_config()
    local dict = ngx.shared.local_waf_cache
    local cached = dict and dict:get("config")
    if cached then
        local cfg = cjson.decode(cached)
        if cfg then return cfg end
    end
    local raw = read_file(config_file) or "{}"
    local cfg = cjson.decode(raw) or {}
    cfg.features = cfg.features or {}
    cfg.lists = cfg.lists or {}
    if dict then dict:set("config", cjson.encode(cfg), 3) end
    return cfg
end

local function list_has(list, value, plain)
    if not value or value == "" then return false end
    for _, item in ipairs(list or {}) do
        if item and item ~= "" then
            if plain then
                if value == item then return true, item end
            else
                local ok, from = pcall(ngx.re.find, value, item, "ijo")
                if ok and from then return true, item end
            end
        end
    end
    return false
end

local function host_in_sites(host, sites)
    if not sites or #sites == 0 then return true end
    host = string.lower((host or ""):gsub(":%d+$", ""))
    for _, site in ipairs(sites or {}) do
        site = string.lower(tostring(site or ""))
        if site == "*" or site == host then return true end
    end
    return false
end

local function log_block(category, rule)
    local dict = ngx.shared.local_waf_cache
    if dict and (category == "automation" or category == "fake_spider") then
        -- A rotating-address flood can generate thousands of identical log rows.
        -- Keep representative evidence without turning the audit log into an I/O load.
        local host = string.lower((ngx.var.host or "-"):gsub(":%d+$", ""))
        local sample_key = "log_sample:" .. ngx.md5(category .. "|" .. tostring(rule or "-") .. "|" .. host)
        if not dict:add(sample_key, true, 15) then return end
    end
    local f = io.open(log_file, "a")
    if not f then return end
    local row = {
        time = os.date("%Y-%m-%d %H:%M:%S"),
        ip = ngx.var.remote_addr or "-",
        host = ngx.var.host or "-",
        method = ngx.var.request_method or "-",
        uri = ngx.var.request_uri or "-",
        ua = ngx.var.http_user_agent or "-",
        category = category,
        rule = rule or "-"
    }
    f:write(cjson.encode(row), "\n")
    f:close()
end

local function deny(cfg, category, rule)
    log_block(category, rule)
    local code = tonumber(cfg.response_code or 403) or 403
    ngx.status = code
    ngx.say("local waf blocked")
    return ngx.exit(code)
end

local function match_rules(value, rules)
    if not value or value == "" then return nil end
    for _, rule in ipairs(rules) do
        local ok, from = pcall(ngx.re.find, value, rule, "ijo")
        if ok and from then return rule end
    end
    return nil
end

local function simple_match(category, value)
    local v = string.lower(value or "")
    if category == "sql" then
        if string.find(v, "union select", 1, true) or
           (string.find(v, "select", 1, true) and string.find(v, " from ", 1, true)) or
           string.find(v, "information_schema", 1, true) or
           string.find(v, "sleep(", 1, true) or
           string.find(v, "benchmark(", 1, true) then
            return "sql_keyword"
        end
    elseif category == "xss" then
        if string.find(v, "<script", 1, true) or string.find(v, "javascript:", 1, true) or
           string.find(v, "onerror=", 1, true) or string.find(v, "onload=", 1, true) then
            return "xss_keyword"
        end
    elseif category == "command" then
        if string.find(v, "/bin/sh", 1, true) or string.find(v, "/bin/bash", 1, true) or
           string.find(v, ";cat ", 1, true) or string.find(v, "|sh", 1, true) then
            return "command_keyword"
        end
    elseif category == "bad_ua" then
        if string.find(v, "sqlmap", 1, true) or string.find(v, "nikto", 1, true) or
           string.find(v, "acunetix", 1, true) or string.find(v, "nessus", 1, true) then
            return "bad_ua_keyword"
        end
    end
    return nil
end

local function is_search_referer(ref)
    local v = string.lower(ref or "")
    return string.find(v, "baidu.com", 1, true) or
           string.find(v, "google.", 1, true) or
           string.find(v, "bing.com", 1, true) or
           string.find(v, "sogou.com", 1, true) or
           string.find(v, "so.com", 1, true) or
           string.find(v, "haosou.com", 1, true) or
           string.find(v, "yahoo.", 1, true) or
           string.find(v, "yandex.", 1, true) or
           string.find(v, "duckduckgo.com", 1, true) or
           string.find(v, "sm.cn", 1, true) or
           string.find(v, "toutiao.com", 1, true) or
           string.find(v, "shenma.com", 1, true)
end

local function is_search_bot_ua(agent)
    local v = string.lower(agent or "")
    return string.find(v, "baiduspider", 1, true) or
           string.find(v, "googlebot", 1, true) or
           string.find(v, "bingbot", 1, true) or
           string.find(v, "duckduckbot", 1, true) or
           string.find(v, "yandexbot", 1, true) or
           string.find(v, "sogou", 1, true) or
           string.find(v, "360spider", 1, true) or
           string.find(v, "haosouspider", 1, true) or
           string.find(v, "bytespider", 1, true) or
           string.find(v, "petalbot", 1, true) or
           string.find(v, "applebot", 1, true)
end

local function spider_type(agent)
    local v = string.lower(agent or "")
    if v == "" then return nil end
    if string.find(v, "googlebot", 1, true) or string.find(v, "storebot-google", 1, true) or
       string.find(v, "google-inspectiontool", 1, true) or string.find(v, "googleother", 1, true) then
        return "google"
    end
    if string.find(v, "bingbot", 1, true) or string.find(v, "bingpreview", 1, true) or
       string.find(v, "adidxbot", 1, true) then return "bing" end
    if string.find(v, "baiduspider", 1, true) then return "baidu" end
    if string.find(v, "sogou", 1, true) then return "sogou" end
    if string.find(v, "360spider", 1, true) or string.find(v, "haosouspider", 1, true) then return "360" end
    if string.find(v, "yisouspider", 1, true) or string.find(v, "shenma", 1, true) then return "shenma" end
    if string.find(v, "duckduckbot", 1, true) then return "duckduckgo" end
    if string.find(v, "yandexbot", 1, true) then return "yandex" end
    if string.find(v, "applebot", 1, true) then return "apple" end
    if string.find(v, "bytespider", 1, true) then return "bytespider" end
    if string.find(v, "petalbot", 1, true) then return "petal" end
    if string.find(v, "slurp", 1, true) or string.find(v, "yahooseeker", 1, true) then return "yahoo" end
    if string.find(v, "semrushbot", 1, true) or string.find(v, "ahrefsbot", 1, true) or
       string.find(v, "mj12bot", 1, true) or string.find(v, "dotbot", 1, true) or
       string.find(v, "blexbot", 1, true) or string.find(v, "serpstatbot", 1, true) or
       string.find(v, "dataforseobot", 1, true) then return "seo_tools" end
    if string.find(v, "spider", 1, true) or string.find(v, "crawler", 1, true) or
       string.find(v, "bot", 1, true) then return "other" end
    return nil
end

local function nginx_var(name)
    local ok, value = pcall(function() return ngx.var[name] end)
    if ok then return value end
    return nil
end

local function verified_spider(kind)
    if kind == "google" then return nginx_var("bt_clean_google_crawler_ip") == "1" end
    if kind == "bing" then return nginx_var("bt_clean_bing_crawler_ip") == "1" end
    if kind == "baidu" then return nginx_var("bt_clean_baidu_crawler_ip") == "1" end
    return false
end

local function is_browser_navigation(mode, dest, accept)
    return string.lower(mode or "") == "navigate" and
           string.lower(dest or "") == "document" and
           (string.find(string.lower(accept or ""), "text/html", 1, true) or
            string.find(string.lower(accept or ""), "application/xhtml+xml", 1, true))
end

local function is_page_request(path, accept)
    local leaf = string.match(path or "", "/([^/]*)$") or ""
    local ext = string.match(string.lower(leaf), "%.([a-z0-9]+)$")
    local static_extensions = {
        css = true, js = true, png = true, jpg = true, jpeg = true,
        gif = true, webp = true, svg = true, ico = true, woff = true,
        woff2 = true, ttf = true, map = true, txt = true, xml = true,
        json = true
    }
    if ext and static_extensions[ext] then
        return false
    end
    local accept_lower = string.lower(accept or "")
    return accept_lower == "" or string.find(accept_lower, "text/html", 1, true) ~= nil or
           string.find(accept_lower, "application/xhtml+xml", 1, true) ~= nil
end

local function explicit_automation_ua(agent)
    local v = string.lower(agent or "")
    local markers = {
        "headlesschrome", "phantomjs", "selenium", "playwright", "puppeteer",
        "cypress/", "nightmare", "htmlunit", "webdriver", "lightpanda"
    }
    for _, marker in ipairs(markers) do
        if string.find(v, marker, 1, true) then return marker end
    end
    return nil
end

local function claimed_browser_ua(agent)
    local v = string.lower(agent or "")
    return string.find(v, "chrome/", 1, true) or string.find(v, "crios/", 1, true) or
           string.find(v, "firefox/", 1, true) or string.find(v, "fxios/", 1, true) or
           string.find(v, "edg/", 1, true) or string.find(v, "safari/", 1, true)
end

local function stale_browser_template(agent)
    local v = string.lower(agent or "")
    local major = string.match(v, "chrome/(%d+)") or
                  string.match(v, "crios/(%d+)") or
                  string.match(v, "firefox/(%d+)") or
                  string.match(v, "fxios/(%d+)") or
                  string.match(v, "edg/(%d+)")
    major = tonumber(major)
    return major ~= nil and major <= 125
end

local function browser_automation_cohort(agent)
    local v = string.lower(agent or "")
    local family = "other"
    if string.find(v, "chrome/", 1, true) or string.find(v, "crios/", 1, true) or
       string.find(v, "edg/", 1, true) then
        family = "chromium"
    elseif string.find(v, "firefox/", 1, true) or string.find(v, "fxios/", 1, true) then
        family = "firefox"
    elseif string.find(v, "safari/", 1, true) then
        family = "safari"
    end

    local platform = "other"
    if string.find(v, "windows", 1, true) then
        platform = "windows"
    elseif string.find(v, "android", 1, true) then
        platform = "android"
    elseif string.find(v, "iphone", 1, true) or string.find(v, "ipad", 1, true) then
        platform = "ios"
    elseif string.find(v, "macintosh", 1, true) or string.find(v, "mac os", 1, true) then
        platform = "mac"
    elseif string.find(v, "linux", 1, true) then
        platform = "linux"
    end
    return family .. ":" .. platform
end

local function bounded_hash(value, buckets)
    local ok, hashed = pcall(ngx.crc32_short, value or "")
    if ok and hashed then return tostring(hashed % buckets) end
    return string.sub(ngx.md5(value or ""), 1, 8)
end

local function automation_site_scope(value)
    local normalized = string.lower((value or ""):gsub(":%d+$", ""))
    if string.match(normalized, "^%d+%.%d+%.%d+%.%d+$") then return normalized end
    return string.match(normalized, "([^.]+%.[^.]+)$") or normalized
end

local function is_unexpected_root_query(uri, args, referer, ua)
    return uri == "/" and args and args ~= "" and
           not is_search_referer(referer) and
           not is_search_bot_ua(ua)
end

local function is_random_query_probe(uri, args, referer, ua)
    if is_search_referer(referer) or is_search_bot_ua(ua) then return false end
    local path = uri or ""
    local leaf = string.match(path, "/([^/]*)$") or ""
    local is_page_path = path == "/" or path == "/index.php" or path == "/index.html" or
                         path == "/index.htm" or not string.find(leaf, ".", 1, true)
    if not is_page_path then return false end
    if not args or args == "" then return false end
    local first = string.match(args, "^([^&]+)")
    if not first then return false end
    local page_num = string.match(first, "^page=(%d+)$") or
                     string.match(first, "^limit=(%d+)$")
    local page_ok = page_num and string.len(page_num) <= 5
    local sort_value = string.match(first, "^sort=([%w_-]+)$") or
                       string.match(first, "^filter=([%w_-]+)$")
    local sort_ok = sort_value == "newest" or sort_value == "latest" or sort_value == "hot" or
                    sort_value == "popular" or sort_value == "views" or sort_value == "date" or
                    sort_value == "time" or sort_value == "rand" or sort_value == "random"
    local category_value = string.match(first, "^category=([%w_-]+)$")
    local category_ok = category_value and string.len(category_value) <= 64
    local date_ok = string.match(first, "^start_date=%d%d%d%d%-%d%d%-%d%d$") ~= nil or
                    string.match(first, "^end_date=%d%d%d%d%-%d%d%-%d%d$") ~= nil
    if not page_ok and not sort_ok and not category_ok and not date_ok then return false end
    local rest = string.match(args, "^[^&]+&(.+)$")
    if not rest then return false end
    local random_parts = 0
    for part in string.gmatch(rest, "[^&]+") do
        local bare_ok = not string.find(part, "=", 1, true) and
                        string.match(part, "^[A-Za-z0-9]+$") and
                        string.len(part) >= 8 and string.len(part) <= 64
        local random_key, random_value = string.match(part, "^([A-Za-z0-9]+)=([A-Za-z0-9]+)$")
        local pair_ok = random_key and random_value and
                        string.len(random_key) >= 8 and string.len(random_key) <= 64 and
                        string.len(random_value) >= 8 and string.len(random_value) <= 64
        if bare_ok or pair_ok then
            random_parts = random_parts + 1
        end
    end
    return random_parts > 0
end

local function is_bare_random_query_probe(uri, args)
    local path = uri or ""
    if path ~= "/" and path ~= "/index.php" and path ~= "/index.html" and path ~= "/index.htm" then
        return false
    end
    local value = args or ""
    local length = string.len(value)
    if length < 6 or length > 64 then return false end
    if string.find(value, "=", 1, true) or string.find(value, "&", 1, true) then return false end
    if not string.match(value, "^[A-Za-z0-9_-]+$") then return false end
    return string.match(value, "[A-Z]") ~= nil and string.match(value, "[a-z]") ~= nil
end

local function ip_to_num(ip)
    local a, b, c, d = string.match(ip or "", "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    return tonumber(a) * 16777216 + tonumber(b) * 65536 + tonumber(c) * 256 + tonumber(d)
end

local function is_private_ip(ip)
    local n = ip_to_num(ip)
    if not n then return true end
    if n >= 167772160 and n <= 184549375 then return true end
    if n >= 2886729728 and n <= 2887778303 then return true end
    if n >= 3232235520 and n <= 3232301055 then return true end
    if n >= 2130706432 and n <= 2147483647 then return true end
    return false
end

local function cidr_match(ipn, cidr)
    local net, bits = string.match(cidr or "", "^(%d+%.%d+%.%d+%.%d+)%/(%d+)$")
    if not net then
        net = cidr
        bits = "32"
    end
    local netn = ip_to_num(net)
    bits = tonumber(bits)
    if not ipn or not netn or not bits then return false end
    local size = 2 ^ (32 - bits)
    return math.floor(ipn / size) == math.floor(netn / size)
end

local function region_match(ip, countries)
    if is_private_ip(ip) then return true, "private" end
    local ipn = ip_to_num(ip)
    if not ipn then return false, "ipv6_or_unknown" end
    for _, code in ipairs(countries or {}) do
        local path = "/www/server/nginx/conf/local_waf/geoip/" .. string.lower(code) .. ".zone"
        local raw = read_file(path)
        if raw then
            for cidr in string.gmatch(raw, "[^\r\n]+") do
                cidr = string.gsub(cidr, "%s+", "")
                if cidr ~= "" and cidr_match(ipn, cidr) then
                    return true, code
                end
            end
        end
    end
    return false, "not_matched"
end

local function china_match(ip)
    if is_private_ip(ip) then return true, "private" end
    local path = "/www/server/nginx/conf/local_waf/geoip/cn.zone"
    if not read_file(path) then return nil, "cn_zone_missing" end
    return region_match(ip, {"CN"})
end

local cfg = load_config()
if cfg.enabled == false then return end
local features = cfg.features or {}
local lists = cfg.lists or {}

local ip = ngx.var.remote_addr or ""
local host = ngx.var.host or ""
local uri = ngx.var.uri or ""
local request_uri = ngx.var.request_uri or ""
local args = ngx.var.args or ""
local ua = ngx.var.http_user_agent or ""
local referer = ngx.var.http_referer or ""
local method = ngx.var.request_method or ""
local content_type = ngx.var.http_content_type or ""
local sec_fetch_mode = ngx.var.http_sec_fetch_mode or ""
local sec_fetch_dest = ngx.var.http_sec_fetch_dest or ""
local sec_fetch_site = ngx.var.http_sec_fetch_site or ""
local accept = ngx.var.http_accept or ""
local accept_language = ngx.var.http_accept_language or ""
local sec_ch_ua = ngx.var.http_sec_ch_ua or ""
local cookie = ngx.var.http_cookie or ""
local x_requested_with = ngx.var.http_x_requested_with or ""
local decoded_request_uri = ngx.unescape_uri(request_uri or "")
local decoded_args = ngx.unescape_uri(args or "")

if list_has(lists.ip_whitelist, ip, true) then return end
local ok = list_has(lists.url_whitelist, request_uri, false); if ok then return end
ok = list_has(lists.ua_whitelist, ua, false); if ok then return end

if features.block_foreign or features.block_china then
    local in_china, reason = china_match(ip)
    if in_china ~= nil then
        if features.block_foreign and not in_china then
            return deny(cfg, "block_foreign", reason)
        end
        if features.block_china and in_china and reason ~= "private" then
            return deny(cfg, "block_china", "CN")
        end
    end
end

local region = cfg.region or {}
if region.enabled then
    local rules = region.rules or {}
    if #rules == 0 and region.countries then
        rules = { region }
    end
    for _, rule in ipairs(rules or {}) do
        if rule.enabled ~= false and host_in_sites(host, rule.sites or {}) then
            local matched, country = region_match(ip, rule.countries or {})
            if rule.mode == "allow" and not matched then
                return deny(cfg, "region_allow", country)
            end
            if rule.mode ~= "allow" and matched and country ~= "private" then
                return deny(cfg, "region_block", country)
            end
        end
    end
end

local ok, rule
ok, rule = list_has(lists.ip_blacklist, ip, true); if ok then return deny(cfg, "ip_blacklist", rule) end
ok, rule = list_has(lists.url_blacklist, request_uri, false); if ok then return deny(cfg, "url_blacklist", rule) end
ok, rule = list_has(lists.ua_blacklist, ua, false); if ok then return deny(cfg, "ua_blacklist", rule) end
ok, rule = list_has(lists.method_blacklist, method, true); if features.method_filter and ok then return deny(cfg, "method_filter", rule) end

-- Spider policies run after explicit IP/URL/UA lists and region controls. An
-- allowed spider only bypasses generic scan and CC heuristics; deterministic
-- exploit signatures below are still checked. Google/Bing/Baidu can require
-- the verified address maps maintained by bt_search_spider_ip_update.sh.
local spider_kind = spider_type(ua)
local trusted_spider = false
if spider_kind then
    local spider_policies = cfg.spiders or {}
    local spider_defaults = {
        google = "verify", bing = "verify", baidu = "verify",
        sogou = "allow", ["360"] = "allow", shenma = "allow",
        duckduckgo = "allow", yandex = "allow", apple = "allow",
        bytespider = "allow", petal = "allow", yahoo = "allow",
        seo_tools = "block", other = "allow"
    }
    local policy = spider_policies[spider_kind] or spider_defaults[spider_kind] or "allow"
    if policy == "block" then
        return deny(cfg, "spider_policy", spider_kind)
    end
    if policy == "verify" then
        if not verified_spider(spider_kind) then
            return deny(cfg, "fake_spider", spider_kind)
        end
        trusted_spider = true
    elseif policy == "allow" then
        trusted_spider = true
    end
end

-- Rotating-referrer browser floods commonly hit only the home page, so the
-- distinct-path detector below cannot see them. Count only strong candidates:
-- a stale fixed browser template, or a claimed external referrer paired with
-- Sec-Fetch-Site:none (an impossible browser navigation combination). This is
-- deliberately separate from search-referrer exemptions because those floods
-- forge Google/Facebook/YouTube referrers. Ordinary CLI clients are not browser
-- claims and therefore remain outside this detector.
if features.automation and not trusted_spider and
   (method == "GET" or method == "HEAD") and
   (uri == "/" or uri == "/index.html" or uri == "/index.htm" or uri == "/index.php") and
   cookie == "" and claimed_browser_ua(ua) then
    local site_lower = string.lower(sec_fetch_site or "")
    local contradictory_referrer = referer ~= "" and site_lower == "none"
    local stale_template = stale_browser_template(ua)
    if contradictory_referrer or stale_template then
        local dict = ngx.shared.local_waf_cache
        local window = tonumber(cfg.automation_window or 10) or 10
        local distributed_limit = tonumber(cfg.automation_distributed_limit or 80) or 80
        local distributed_ip_limit = tonumber(cfg.automation_distributed_ip_limit or 12) or 12
        local block_time = tonumber(cfg.automation_block_time or 300) or 300
        local site_scope = automation_site_scope(host)
        local prefix = "automation_entry:" .. site_scope
        local block_key = prefix .. ":block"
        if dict:get(block_key) then
            return deny(cfg, "automation", "rotating_home_block")
        end
        local requests = dict:incr(prefix .. ":requests", 1, 0, window)
        local ips = tonumber(dict:get(prefix .. ":ips") or 0) or 0
        local ip_key = prefix .. ":ip:" .. bounded_hash(ip, 1024)
        if dict:add(ip_key, true, window) then
            ips = dict:incr(prefix .. ":ips", 1, 0, window)
        end
        if requests > math.max(240, distributed_limit * 3) and
           ips > math.max(36, distributed_ip_limit * 3) then
            dict:set(block_key, true, math.max(30, math.min(block_time, 120)))
            return deny(cfg, "automation", "rotating_home_flood,requests=" ..
                tostring(requests) .. ",ips=" .. tostring(ips))
        end
    end
end

-- Detect automation that claims a normal browser UA. Static assets are ignored,
-- while page navigation is evaluated by request rate, distinct-path behavior and
-- browser-header consistency. A single missing header never blocks a visitor.
if features.automation and not trusted_spider and not is_search_referer(referer) and
   (method == "GET" or method == "HEAD") and is_page_request(uri, accept) then
    local marker = explicit_automation_ua(ua)
    if marker then
        return deny(cfg, "automation", "explicit=" .. marker)
    end

    local browser_claim = claimed_browser_ua(ua)
    local browser_navigation = is_browser_navigation(sec_fetch_mode, sec_fetch_dest, accept)
    local guide_entry_route = string.match(uri, "^/guides/[^/?]+/?$") ~= nil
    local normal_entry_route = uri == "/" or uri == "/index.html" or guide_entry_route
    local score = 0
    if browser_claim then
        if sec_fetch_mode == "" and sec_fetch_dest == "" then score = score + 1 end
        if accept_language == "" then score = score + 1 end
        if cookie == "" and referer == "" then score = score + 1 end
        local ua_lower_for_automation = string.lower(ua or "")
        local chromium_claim = string.find(ua_lower_for_automation, "chrome/", 1, true) or
                               string.find(ua_lower_for_automation, "crios/", 1, true) or
                               string.find(ua_lower_for_automation, "edg/", 1, true)
        if chromium_claim and sec_ch_ua == "" then score = score + 1 end
        if browser_navigation then score = math.max(0, score - 2) end
    elseif ua == "" then
        score = score + 2
    end
    if x_requested_with ~= "" and string.lower(x_requested_with) ~= "xmlhttprequest" then
        score = score + 1
    end

    local dict = ngx.shared.local_waf_cache
    local scope = ip .. ":" .. host
    local block_key = "automation_block:" .. scope
    if dict:get(block_key) then
        return deny(cfg, "automation", "temporary_block")
    end
    local window = tonumber(cfg.automation_window or 10) or 10
    local limit = tonumber(cfg.automation_limit or 120) or 120
    local distinct_limit = tonumber(cfg.automation_distinct_limit or 24) or 24
    local distributed_limit = tonumber(cfg.automation_distributed_limit or 80) or 80
    local distributed_ip_limit = tonumber(cfg.automation_distributed_ip_limit or 12) or 12
    local block_time = tonumber(cfg.automation_block_time or 300) or 300
    local requests = dict:incr("automation_req:" .. scope, 1, 0, window)
    local distinct_key = "automation_seen:" .. scope .. ":" .. ngx.md5(uri .. "?" .. args)
    local distinct = tonumber(dict:get("automation_distinct:" .. scope) or 0) or 0
    if dict:add(distinct_key, true, window) then
        distinct = dict:incr("automation_distinct:" .. scope, 1, 0, window)
    end

    -- Distributed automation keeps each source below the per-IP threshold. Build
    -- a bounded browser fingerprint and count source/path buckets across IPs.
    -- Bucketed keys cap shared-memory use during a large rotating-address flood.
    local fingerprint_material = string.lower(ua or "") .. "|" ..
                                 string.lower(sec_fetch_mode or "") .. "|" ..
                                 string.lower(sec_fetch_dest or "")
    local fingerprint = ngx.md5(fingerprint_material)
    local site_scope = automation_site_scope(host)
    local fp_scope = site_scope .. ":" .. fingerprint
    local global_scope = "all:" .. fingerprint
    local fp_block_key = "automation_fp_block:" .. fp_scope
    local global_block_key = "automation_fp_block:" .. global_scope
    if (not normal_entry_route or guide_entry_route) and
       (dict:get(fp_block_key) or dict:get(global_block_key)) then
        return deny(cfg, "automation", "distributed_fingerprint_block")
    end

    local function distributed_counters(prefix, ip_buckets, path_buckets, path_material)
        local req_count = dict:incr("automation_fp_req:" .. prefix, 1, 0, window)
        local ip_count = tonumber(dict:get("automation_fp_ips:" .. prefix) or 0) or 0
        local ip_key = "automation_fp_ip:" .. prefix .. ":" .. bounded_hash(ip, ip_buckets or 256)
        if dict:add(ip_key, true, window) then
            ip_count = dict:incr("automation_fp_ips:" .. prefix, 1, 0, window)
        end
        local path_count = tonumber(dict:get("automation_fp_paths:" .. prefix) or 0) or 0
        local path_key = "automation_fp_path:" .. prefix .. ":" ..
                         bounded_hash(path_material or (uri .. "?" .. args), path_buckets or 128)
        if dict:add(path_key, true, window) then
            path_count = dict:incr("automation_fp_paths:" .. prefix, 1, 0, window)
        end
        return req_count, ip_count, path_count
    end

    local fp_requests, fp_ips, fp_paths = distributed_counters(fp_scope)
    local global_requests, global_ips, global_paths = distributed_counters(global_scope)

    -- Some automation rotates both its IP and User-Agent. Count first-visit,
    -- cookie-less page enumeration per base domain so changing fingerprints no
    -- longer bypasses the distributed detector. Valid guide pages stay available
    -- to ordinary visitors, but are included once traffic is distributed across
    -- many addresses and many paths at abnormal volume. Search referrals are
    -- excluded above and established browser sessions keep their normal lane.
    local site_requests, site_ips, site_paths = 0, 0, 0
    local site_distributed_flood = false
    if browser_claim and cookie == "" and (not normal_entry_route or guide_entry_route) then
        site_requests, site_ips, site_paths = distributed_counters("site:" .. site_scope)
        site_distributed_flood =
            site_requests > math.max(480, distributed_limit * 6) and
            site_ips > math.max(48, distributed_ip_limit * 4) and
            site_paths > math.max(96, distinct_limit * 4)
    end

    -- Large browser-emulation floods rotate the address, hostname, path and
    -- exact browser version together. Group those mutable fingerprints by
    -- browser family and operating system, then require high request volume,
    -- source diversity and route diversity across the whole origin. This keeps
    -- ordinary first visits below the threshold while closing the cross-site
    -- rotation bypass. Search referrals and verified crawlers are excluded by
    -- the outer condition; established cookie sessions stay in the normal lane.
    local cohort_requests, cohort_ips, cohort_paths = 0, 0, 0
    local cohort_flood = false
    local cohort = nil
    local cohort_block_key = nil
    -- A browser family/OS pair is far too broad to block on its own: real users
    -- commonly share it across many hosted domains. Only admit a request into
    -- the cross-site cohort detector when it has multiple header anomalies, is
    -- not a normal browser navigation, and is not one of the site's legitimate
    -- high-volume entry routes. Per-IP rate and exact-fingerprint protection
    -- above remain active for every route.
    local cohort_candidate = guide_entry_route or
        (score >= 2 and not browser_navigation and not normal_entry_route)
    if browser_claim and cookie == "" and cohort_candidate then
        cohort = browser_automation_cohort(ua)
        cohort_block_key = "automation_cohort_block:" .. cohort
        if dict:get(cohort_block_key) then
            return deny(cfg, "automation", "rotating_browser_cohort_block=" .. cohort)
        end
        cohort_requests, cohort_ips, cohort_paths = distributed_counters(
            "cohort:" .. cohort, 2048, 4096, host .. "|" .. uri .. "?" .. args
        )
        cohort_flood =
            cohort_requests > math.max(1200, distributed_limit * 15) and
            cohort_ips > math.max(96, distributed_ip_limit * 8) and
            cohort_paths > math.max(192, distinct_limit * 8)
    end
    local score_factor = score >= 1 and 1 or 2
    local distributed_flood = (not normal_entry_route or guide_entry_route) and
        fp_requests > distributed_limit * score_factor and
        fp_ips > distributed_ip_limit * score_factor and
        fp_paths > distinct_limit * score_factor
    local global_distributed_flood = not normal_entry_route and
        global_requests > distributed_limit * 4 * score_factor and
        global_ips > distributed_ip_limit * 2 * score_factor and
        global_paths > distinct_limit * 2 * score_factor
    local suspicious = score >= 2 and requests > math.max(12, math.floor(limit / 6))
    local path_enumeration = distinct > distinct_limit and
                             (score >= 1 or distinct > distinct_limit * 2)
    local browser_flood = requests > limit
    if suspicious or path_enumeration or browser_flood or
       distributed_flood or global_distributed_flood or site_distributed_flood or
       cohort_flood then
        dict:set(block_key, true, block_time)
        if distributed_flood then
            dict:set(fp_block_key, true, math.max(30, math.min(block_time, 120)))
        end
        if global_distributed_flood then
            dict:set(global_block_key, true, math.max(30, math.min(block_time, 120)))
        end
        if cohort_flood and cohort_block_key then
            dict:set(cohort_block_key, true, math.max(30, math.min(block_time, 90)))
        end
        local reason = "score=" .. tostring(score) .. ",requests=" .. tostring(requests) ..
                       ",distinct=" .. tostring(distinct) ..
                       ",fp_requests=" .. tostring(fp_requests) ..
                       ",fp_ips=" .. tostring(fp_ips) ..
                       ",fp_paths=" .. tostring(fp_paths) ..
                       ",global_requests=" .. tostring(global_requests) ..
                       ",global_ips=" .. tostring(global_ips) ..
                       ",global_paths=" .. tostring(global_paths) ..
                       ",site_requests=" .. tostring(site_requests) ..
                       ",site_ips=" .. tostring(site_ips) ..
                       ",site_paths=" .. tostring(site_paths) ..
                       ",cohort=" .. tostring(cohort or "") ..
                       ",cohort_requests=" .. tostring(cohort_requests) ..
                       ",cohort_ips=" .. tostring(cohort_ips) ..
                       ",cohort_paths=" .. tostring(cohort_paths)
        return deny(cfg, "automation", reason)
    end
end

-- Guide slugs are a valid high-volume route. IP, region, allow/deny lists and
-- method checks have already run above, so a bodyless and queryless guide GET
-- can skip the generic payload regexes below without weakening route controls.
local ua_lower = string.lower(ua or "")
local known_attack_tool =
    string.find(ua_lower, "sqlmap", 1, true) or
    string.find(ua_lower, "nikto", 1, true) or
    string.find(ua_lower, "acunetix", 1, true) or
    string.find(ua_lower, "nessus", 1, true) or
    string.find(ua_lower, "masscan", 1, true) or
    string.find(ua_lower, "zgrab", 1, true)
local safe_guide_path =
    string.match(uri, "^/guides/[A-Za-z0-9%-]+$") or
    string.match(uri, "^/[a-z][a-z]/guides/[A-Za-z0-9%-]+$")
if (method == "GET" or method == "HEAD") and args == "" and
   string.len(uri) <= 220 and safe_guide_path and not known_attack_tool then
    return
end

if features.sensitive_path and not trusted_spider and is_unexpected_root_query(uri, args, referer, ua) then
    return deny(cfg, "sensitive_path", "unexpected_root_query")
end

if features.sensitive_path and not trusted_spider and is_random_query_probe(uri, args, referer, ua) then
    return deny(cfg, "sensitive_path", "random_query_probe")
end

if features.sensitive_path and not trusted_spider and is_bare_random_query_probe(uri, args) then
    return deny(cfg, "sensitive_path", "bare_random_query_probe")
end

-- Detect rapid path enumeration without blocking an individual legitimate path.
-- Browser fetches and verified/search crawler user agents are excluded here; query
-- abuse and known exploit paths are handled by the deterministic rules above.
if features.sensitive_path and (method == "GET" or method == "HEAD") and
   sec_fetch_mode == "" and referer == "" and not trusted_spider then
    local dict = ngx.shared.local_waf_cache
    local scan_scope = ip .. ":" .. host
    local blocked_key = "path_scan_block:" .. scan_scope
    if dict:get(blocked_key) then
        return deny(cfg, "sensitive_path", "path_enumeration_blocked")
    end
    local static_file = match_rules(string.lower(uri), {
        [[\.(?:css|js|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|map|txt|xml)$]]
    })
    if not static_file and string.len(uri) <= 160 then
        local scan_window = tonumber(cfg.scan_window or 10) or 10
        local scan_limit = tonumber(cfg.scan_limit or 6) or 6
        local seen_key = "path_scan_seen:" .. scan_scope .. ":" .. ngx.md5(uri)
        if dict:add(seen_key, true, scan_window) then
            local count_key = "path_scan_count:" .. scan_scope
            local scan_count = dict:incr(count_key, 1, 0, scan_window)
            if scan_count > scan_limit then
                dict:set(blocked_key, true, tonumber(cfg.scan_block_time or 60) or 60)
                return deny(cfg, "sensitive_path", "path_enumeration=" .. tostring(scan_count))
            end
        end
    end
end

if features.cc then
    local dict = ngx.shared.local_waf_cache
    local key = "cc:" .. ip .. ":" .. uri
    local n = dict:incr(key, 1, 0, tonumber(cfg.cc_window or 10) or 10)
    if n > (tonumber(cfg.cc_limit or 60) or 60) then
        return deny(cfg, "cc", "limit=" .. tostring(n))
    end
    local landing = uri == "/" or uri == "/index.php" or uri == "/index.html" or uri == "/index.htm"
    if landing and (method == "GET" or method == "HEAD") and
       not trusted_spider and
       not is_browser_navigation(sec_fetch_mode, sec_fetch_dest, accept) then
        local distributed_window = tonumber(cfg.distributed_window or 5) or 5
        local distributed_limit = tonumber(cfg.distributed_limit or 120) or 120
        local distributed_key = "cc_distributed:" .. host .. ":" .. uri
        local distributed_n = dict:incr(distributed_key, 1, 0, distributed_window)
        if distributed_n > distributed_limit then
            return deny(cfg, "cc_distributed", "limit=" .. tostring(distributed_n))
        end
    end
end

local sql_rules = {
    [[(?:union(?:\s|/\*.*?\*/)+select|select.+from|insert\s+into|drop\s+table|information_schema)]],
    [[(?:sleep|benchmark)\s*\(]], [[(?:load_file|outfile)\s*\(]],
    [[(?:\b(?:or|and)\b\s+\d+\s*=\s*\d+)]]
}
local xss_rules = { [[(?:<script|javascript:|onerror\s*=|onload\s*=|<iframe|document\.cookie)]] }
local cmd_rules = { [[(?:;|\||&&|\$\(|`)\s*(?:cat|bash|sh|wget|curl|nc|python|perl)\b]], [[/(?:bin/sh|bin/bash)\b]] }
local path_rules = {
    [[\.\./]], [[/(?:etc/passwd|proc/self|root/\.ssh)]], [[\.(?:git|svn|hg)(?:/|$)]],
    [[/(?:\.env|composer\.(?:json|lock)|wp-config\.php)]],
    [[^/\?=[A-Za-z0-9_-]{4,128}(?:&|$)]],
    [[^/(?:Telerik\.Web\.UI\.)?WebResource\.axd\?(?:[^&]*&)*type=rau(?:&|$)]]
}
local php_rules = { [[(?:eval|assert|system|shell_exec|passthru|base64_decode)\s*\(]], [[(?:\$_(?:GET|POST|REQUEST|COOKIE)\[)]] }
local weak_rules = { [[(?:password|passwd|pwd)=?(?:123456|admin|root|123|111111)]], [[/(?:phpmyadmin|pma|adminer)(?:/|$)]] }
local upload_rules = {
    [[filename\s*=\s*["']?[^"';]+\.(?:php[0-9]?|phtml|phar|jsp|asp|aspx)\b]],
    [[multipart/form-data.*(?:php|phtml|phar)]]
}
-- Generic HTTP clients are legitimate automation tools. Only block user agents
-- that identify explicit vulnerability scanners or attack tooling.
local bad_ua_rules = { [[(?:sqlmap|nikto|acunetix|nessus|masscan|zgrab)]] }

local joined = request_uri .. " " .. decoded_request_uri .. " " .. args .. " " .. decoded_args .. " " .. content_type
local upload_joined = content_type
if method == "POST" or method == "PUT" or method == "PATCH" then
    ngx.req.read_body()
    local body = ngx.req.get_body_data() or ""
    upload_joined = content_type .. " " .. body
end
local checks = {
    {"sql", features.sql, joined, sql_rules},
    {"xss", features.xss, joined, xss_rules},
    {"command", features.command, joined, cmd_rules},
    {"sensitive_path", features.sensitive_path, request_uri, path_rules},
    {"php_code", features.php_code, joined, php_rules},
    {"weak_password", features.weak_password, joined, weak_rules},
    {"upload", features.upload, upload_joined, upload_rules},
    {"bad_ua", features.bad_ua, ua, bad_ua_rules},
    {"custom", features.custom, joined .. " " .. ua, lists.custom_rules or {}}
}
for _, c in ipairs(checks) do
    if c[2] then
        local r = simple_match(c[1], c[3]) or match_rules(c[3], c[4])
        if r then return deny(cfg, c[1], r) end
    end
end
EOF
  cat > "$PLUGIN_DIR/info.json" <<'EOF'
{"name":"local_waf","title":"\u672c\u5730Nginx\u57fa\u7840WAF","version":"1.2","ps":"\u514d\u8d39\u672c\u5730 Lua WAF\uff0c\u652f\u6301\u8718\u86db\u5206\u7c7b\u653e\u884c\u3001\u5b98\u65b9 IP \u9a8c\u8bc1\u548c\u5c4f\u853d\u7b56\u7565"}
EOF
  cat > "$PLUGIN_DIR/local_waf_main.py" <<'EOF'
# coding: utf-8
import json
import os
import re
import time
import urllib.request

import public


class local_waf_main:
    waf_dir = "/www/server/nginx/conf/local_waf"
    nginx_conf = "/www/server/nginx/conf/nginx.conf"
    include_line = "    include /www/server/nginx/conf/local_waf/local_waf.conf;"
    config_file = waf_dir + "/config.json"
    log_file = waf_dir + "/waf.log"
    install_time_file = waf_dir + "/install.time"
    geoip_dir = waf_dir + "/geoip"
    cloudflare_tool = "/www/server/panel/script/bt_cloudflare_origin_lock.sh"
    cloudflare_state = "/www/server/panel/data/cloudflare_origin_lock/enabled"
    country_map = {
        "CN": "中国大陆", "HK": "中国香港", "MO": "中国澳门", "TW": "中国台湾",
        "US": "美国", "GB": "英国", "AU": "澳大利亚", "CA": "加拿大", "NZ": "新西兰",
        "RU": "俄罗斯", "UA": "乌克兰", "BY": "白俄罗斯", "DE": "德国", "FR": "法国",
        "JP": "日本", "KR": "韩国", "SG": "新加坡", "MY": "马来西亚", "NO": "挪威",
        "SE": "瑞典", "FI": "芬兰", "IE": "爱尔兰", "NL": "荷兰", "DK": "丹麦",
        "IT": "意大利", "ES": "西班牙", "ASIA": "亚洲", "EU": "欧洲",
        "NA": "北美洲", "SA": "南美洲", "OC": "大洋洲", "AF": "非洲",
    }

    def a(self, get=None):
        return public.returnMsg(True, "ok")

    def _default_config(self):
        return {
            "enabled": True,
            "response_code": 403,
            "cc_window": 10,
            "cc_limit": 60,
            "scan_window": 10,
            "scan_limit": 6,
            "scan_block_time": 60,
            "automation_window": 10,
            "automation_limit": 120,
            "automation_distinct_limit": 24,
            "automation_distributed_limit": 80,
            "automation_distributed_ip_limit": 12,
            "automation_block_time": 300,
            "features": {
                "cc": True, "sql": True, "xss": True, "command": True,
                "weak_password": True, "sensitive_path": True, "php_code": True,
                "upload": True, "bad_ua": True, "method_filter": True,
                "block_foreign": False, "block_china": False, "custom": True,
                "automation": True,
            },
            "spiders": {
                "google": "verify", "bing": "verify", "baidu": "verify",
                "sogou": "allow", "360": "allow", "shenma": "allow",
                "duckduckgo": "allow", "yandex": "allow", "apple": "allow",
                "bytespider": "allow", "petal": "allow", "yahoo": "allow",
                "seo_tools": "block", "other": "allow",
            },
            "region": {"enabled": False, "mode": "block", "countries": [], "sites": [], "rules": []},
            "lists": {
                "ip_whitelist": ["127.0.0.1", "::1"], "ip_blacklist": [],
                "ua_whitelist": [], "ua_blacklist": [],
                "url_whitelist": [], "url_blacklist": [],
                "method_blacklist": ["TRACE"], "custom_rules": [],
            }
        }

    def _read_json(self):
        try:
            data = json.loads(public.readFile(self.config_file) or "{}")
        except Exception:
            data = {}
        cfg = self._default_config()
        for key, value in data.items():
            if key not in ("features", "lists", "region", "spiders"):
                cfg[key] = value
        cfg["features"].update(data.get("features", {}) if isinstance(data.get("features", {}), dict) else {})
        cfg["lists"].update(data.get("lists", {}) if isinstance(data.get("lists", {}), dict) else {})
        cfg["region"].update(data.get("region", {}) if isinstance(data.get("region", {}), dict) else {})
        cfg["spiders"].update(data.get("spiders", {}) if isinstance(data.get("spiders", {}), dict) else {})
        raw_region = data.get("region", {}) if isinstance(data.get("region", {}), dict) else {}
        cfg["region"]["rules"] = cfg["region"].get("rules") or []
        if "rules" not in raw_region and not cfg["region"]["rules"] and cfg["region"].get("countries"):
            cfg["region"]["rules"].append({
                "id": str(int(time.time() * 1000)),
                "enabled": bool(cfg["region"].get("enabled")),
                "mode": cfg["region"].get("mode", "block"),
                "countries": cfg["region"].get("countries", []),
                "sites": cfg["region"].get("sites", []),
            })
        return cfg

    def _write_json(self, cfg):
        public.writeFile(self.config_file, json.dumps(cfg, ensure_ascii=False, indent=2))

    def _reload(self):
        out, err = public.ExecShell("/www/server/nginx/sbin/nginx -t && /www/server/nginx/sbin/nginx -s reload")
        if err and "successful" not in err:
            return public.returnMsg(False, err)
        return public.returnMsg(True, "操作成功")

    def _enabled_in_nginx(self):
        body = public.readFile(self.nginx_conf) or ""
        return "local_waf/local_waf.conf" in body

    def _set_nginx_include(self, enabled):
        body = public.readFile(self.nginx_conf) or ""
        if enabled and "local_waf/local_waf.conf" not in body:
            pos = body.find("http")
            brace = body.find("{", pos)
            if pos == -1 or brace == -1:
                return public.returnMsg(False, "没有找到 nginx http 配置块")
            body = body[:brace + 1] + "\n" + self.include_line + body[brace + 1:]
            public.writeFile(self.nginx_conf, body)
        if not enabled:
            body = body.replace("\n" + self.include_line, "").replace(self.include_line + "\n", "")
            public.writeFile(self.nginx_conf, body)
        return self._reload()

    def _tail_log_lines(self, limit=1000, max_bytes=4 * 1024 * 1024):
        """Read only the end of the WAF log so the panel stays responsive."""
        if not os.path.exists(self.log_file):
            return []
        try:
            size = os.path.getsize(self.log_file)
            offset = max(0, size - max_bytes)
            with open(self.log_file, "rb") as fp:
                fp.seek(offset)
                raw = fp.read()
            if offset:
                newline = raw.find(b"\n")
                raw = raw[newline + 1:] if newline >= 0 else b""
            return raw.decode("utf-8", "replace").splitlines()[-limit:]
        except Exception:
            return []

    def _parse_logs(self):
        rows, stats = [], {}
        for line in self._tail_log_lines():
            try:
                row = json.loads(line)
            except Exception:
                continue
            rows.append(row)
            c = row.get("category", "other")
            stats[c] = stats.get(c, 0) + 1
        return rows, stats

    def _get_sites(self):
        names = []
        try:
            rows = public.M("sites").field("name").select()
            for row in rows or []:
                name = row.get("name")
                if name and name not in names:
                    names.append(name)
        except Exception:
            pass
        vhost_dir = "/www/server/panel/vhost/nginx"
        if os.path.exists(vhost_dir):
            for fn in os.listdir(vhost_dir):
                if not fn.endswith(".conf"):
                    continue
                body = public.readFile(os.path.join(vhost_dir, fn)) or ""
                for line in body.splitlines():
                    line = line.strip()
                    if not line.startswith("server_name"):
                        continue
                    for item in line.replace("server_name", "").replace(";", "").split():
                        if item and item != "_" and item not in names:
                            names.append(item)
        return names

    def get_status(self, get=None):
        cfg = self._read_json()
        rows, stats = self._parse_logs()
        install_time = int(public.readFile(self.install_time_file) or time.time())
        safe_days = max(1, int((time.time() - install_time) / 86400) + 1)
        synced = {}
        if os.path.exists(self.geoip_dir):
            for fn in os.listdir(self.geoip_dir):
                if fn.endswith(".zone"):
                    path = os.path.join(self.geoip_dir, fn)
                    synced[fn[:-5].upper()] = {
                        "count": len([x for x in (public.readFile(path) or "").splitlines() if x.strip()]),
                        "mtime": int(os.path.getmtime(path)),
                    }
        return {
            "status": True,
            "enabled": cfg.get("enabled") and self._enabled_in_nginx(),
            "config": cfg,
            "countries": self.country_map,
            "sites": self._get_sites(),
            "synced_regions": synced,
            "stats": stats,
            "risk_total": sum(stats.values()),
            "safe_days": safe_days,
            "cloudflare_origin": {
                "enabled": os.path.exists(self.cloudflare_state),
                "available": os.path.exists(self.cloudflare_tool),
            },
            "log": "\n".join([json.dumps(x, ensure_ascii=False) for x in rows[-200:]]),
            "paths": {
                "rules": self.waf_dir + "/waf.lua",
                "config": self.config_file,
                "log": self.log_file,
                "nginx": self.nginx_conf,
            }
        }

    def set_cloudflare_origin(self, get):
        enabled = str(get.get("enabled", "1")) in ("1", "true", "True", "on")
        if not os.path.exists(self.cloudflare_tool):
            return public.returnMsg(False, "Cloudflare origin lock tool is not installed")
        action = "apply" if enabled else "remove"
        out, err = public.ExecShell("/bin/bash {} {}".format(self.cloudflare_tool, action))
        state_ok = os.path.exists(self.cloudflare_state) == enabled
        if not state_ok:
            message = (err or out or "Cloudflare origin lock failed").strip()
            return public.returnMsg(False, message)
        return public.returnMsg(True, {
            "enabled": enabled,
            "message": (out or "ok").strip(),
        })

    def set_enable(self, get):
        enabled = str(get.get("enabled", "1")) in ("1", "true", "True", "on")
        cfg = self._read_json()
        cfg["enabled"] = enabled
        self._write_json(cfg)
        return self._set_nginx_include(enabled)

    def save_config(self, get):
        cfg = self._read_json()
        try:
            incoming = json.loads(get.get("config", "{}"))
        except Exception as e:
            return public.returnMsg(False, "配置JSON错误: {}".format(e))
        cfg.update({k: v for k, v in incoming.items() if k not in ("features", "lists", "spiders")})
        cfg["features"].update(incoming.get("features", {}))
        cfg["lists"].update(incoming.get("lists", {}))
        cfg["spiders"].update(incoming.get("spiders", {}))
        cfg["response_code"] = int(cfg.get("response_code", 403))
        cfg["cc_window"] = int(cfg.get("cc_window", 10))
        cfg["cc_limit"] = int(cfg.get("cc_limit", 60))
        cfg["scan_window"] = int(cfg.get("scan_window", 10))
        cfg["scan_limit"] = int(cfg.get("scan_limit", 6))
        cfg["scan_block_time"] = int(cfg.get("scan_block_time", 60))
        cfg["automation_window"] = max(2, min(60, int(cfg.get("automation_window", 10))))
        cfg["automation_limit"] = max(20, min(5000, int(cfg.get("automation_limit", 120))))
        cfg["automation_distinct_limit"] = max(5, min(1000, int(cfg.get("automation_distinct_limit", 24))))
        cfg["automation_distributed_limit"] = max(20, min(5000, int(cfg.get("automation_distributed_limit", 80))))
        cfg["automation_distributed_ip_limit"] = max(4, min(1000, int(cfg.get("automation_distributed_ip_limit", 12))))
        cfg["automation_block_time"] = max(10, min(86400, int(cfg.get("automation_block_time", 300))))
        self._write_json(cfg)
        return self._reload()

    def set_feature(self, get):
        key = get.get("key")
        enabled = str(get.get("enabled", "1")) in ("1", "true", "True", "on")
        cfg = self._read_json()
        if key not in cfg["features"]:
            return public.returnMsg(False, "功能不存在: " + str(key))
        cfg["features"][key] = enabled
        self._write_json(cfg)
        return self._reload()

    def set_spider_policy(self, get):
        key = str(get.get("key", "")).strip()
        policy = str(get.get("policy", "allow")).strip().lower()
        cfg = self._read_json()
        if key not in cfg["spiders"]:
            return public.returnMsg(False, "蜘蛛类型不存在: " + key)
        allowed = ("allow", "block")
        if key in ("google", "bing", "baidu"):
            allowed = ("allow", "verify", "block")
        if policy not in allowed:
            return public.returnMsg(False, "不支持的策略: " + policy)
        cfg["spiders"][key] = policy
        self._write_json(cfg)
        res = self._reload()
        if isinstance(res, dict) and not res.get("status"):
            return res
        return public.returnMsg(True, {"key": key, "policy": policy})

    def save_list(self, get):
        key = get.get("key")
        cfg = self._read_json()
        if key not in cfg["lists"]:
            return public.returnMsg(False, "名单不存在: " + str(key))
        lines = []
        for line in (get.get("value", "") or "").replace("\r", "").split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
        cfg["lists"][key] = lines
        self._write_json(cfg)
        return self._reload()

    def save_region(self, get):
        cfg = self._read_json()
        mode = get.get("mode", "block")
        if mode not in ("block", "allow"):
            return public.returnMsg(False, "invalid region mode")
        countries = []
        try:
            raw = json.loads(get.get("countries", "[]"))
        except Exception:
            raw = []
        for code in raw:
            code = str(code).upper().strip()
            if code and code not in countries:
                countries.append(code)
        if not countries:
            try:
                public.writeFile(self.waf_dir + "/region-debug.log", "raw countries=" + str(get.get("countries", "")) + " raw sites=" + str(get.get("sites", "")) + "\n", "a+")
            except Exception:
                pass
            return public.returnMsg(False, "select region first")
        try:
            raw_sites = json.loads(get.get("sites", "[]"))
        except Exception:
            raw_sites = []
        sites = []
        for site in raw_sites:
            site = str(site).strip().lower()
            if site and site not in sites:
                sites.append(site)
        region = cfg.get("region", {})
        rules = region.get("rules") or []
        rule = {
            "id": str(int(time.time() * 1000)),
            "enabled": True,
            "mode": mode,
            "countries": countries,
            "sites": sites,
        }
        rules.append(rule)
        cfg["region"] = {"enabled": True, "mode": mode, "countries": countries, "sites": sites, "rules": rules}
        self._write_json(cfg)
        res = self._reload()
        if isinstance(res, dict) and not res.get("status"):
            return res
        return public.returnMsg(True, {"region": cfg.get("region", {}), "rule": rule})

    def delete_region(self, get):
        cfg = self._read_json()
        rid = str(get.get("id", ""))
        rules = cfg.get("region", {}).get("rules") or []
        if rid:
            rules = [x for x in rules if str(x.get("id", "")) != rid]
        else:
            try:
                idx = int(get.get("index", -1))
            except Exception:
                idx = -1
            if 0 <= idx < len(rules):
                rules.pop(idx)
        cfg["region"]["rules"] = rules
        cfg["region"]["enabled"] = bool(rules)
        if not rules:
            cfg["region"]["countries"] = []
            cfg["region"]["sites"] = []
        self._write_json(cfg)
        res = self._reload()
        if isinstance(res, dict) and not res.get("status"):
            return res
        return public.returnMsg(True, {"region": cfg.get("region", {})})

    def sync_region(self, get):
        cfg = self._read_json()
        countries = []
        for rule in cfg.get("region", {}).get("rules", []) or []:
            for code in rule.get("countries", []) or []:
                code = str(code).upper().strip()
                if code and code not in countries:
                    countries.append(code)
        if not countries:
            countries = cfg.get("region", {}).get("countries", [])
        if get and get.get("countries"):
            try:
                countries = json.loads(get.get("countries", "[]"))
            except Exception:
                countries = []
            countries = [str(x).upper().strip() for x in countries if str(x).strip()]
        if not countries:
            return public.returnMsg(False, "add or select region first")
        if not os.path.exists(self.geoip_dir):
            os.makedirs(self.geoip_dir)
        ok, fail = [], []
        for code in countries:
            code = str(code).lower()
            if len(code) != 2:
                fail.append(code.upper())
                continue
            url = "https://www.ipdeny.com/ipblocks/data/aggregated/{}-aggregated.zone".format(code)
            try:
                data = urllib.request.urlopen(url, timeout=15).read().decode("utf-8", "ignore")
                lines = [x.strip() for x in data.splitlines() if x.strip() and not x.startswith("#")]
                if not lines:
                    raise ValueError("empty")
                public.writeFile(os.path.join(self.geoip_dir, code + ".zone"), "\n".join(lines) + "\n")
                ok.append(code.upper())
            except Exception:
                fail.append(code.upper())
        public.writeFile(os.path.join(self.geoip_dir, "sync.time"), str(int(time.time())))
        synced = {}
        for code in ok:
            path = os.path.join(self.geoip_dir, code.lower() + ".zone")
            synced[code] = {
                "count": len([x for x in (public.readFile(path) or "").splitlines() if x.strip()]),
                "mtime": int(os.path.getmtime(path)) if os.path.exists(path) else int(time.time()),
            }
        return {"status": True, "ok": ok, "fail": fail, "synced": synced, "msg": "sync done: {} ok, {} failed".format(len(ok), len(fail))}

    def get_region_info(self, get=None):
        cfg = self._read_json()
        synced = {}
        if os.path.exists(self.geoip_dir):
            for fn in os.listdir(self.geoip_dir):
                if not fn.endswith(".zone"):
                    continue
                path = os.path.join(self.geoip_dir, fn)
                synced[fn[:-5].upper()] = {
                    "count": len([x for x in (public.readFile(path) or "").splitlines() if x.strip()]),
                    "mtime": int(os.path.getmtime(path)),
                }
        return {"status": True, "region": cfg.get("region", {}), "countries": self.country_map, "synced": synced}

    def get_log(self, get=None):
        rows, stats = self._parse_logs()
        return {"status": True, "stats": stats, "log": "\n".join(json.dumps(x, ensure_ascii=False) for x in rows[-300:])}

    def clear_log(self, get=None):
        public.writeFile(self.log_file, "")
        return public.returnMsg(True, "日志已清空")

    def export_config(self, get=None):
        return {"status": True, "config": json.dumps(self._read_json(), ensure_ascii=False, indent=2)}

    def import_config(self, get):
        try:
            cfg = json.loads(get.get("config", "{}"))
        except Exception as e:
            return public.returnMsg(False, "导入失败: {}".format(e))
        self._write_json(cfg)
        return self._reload()

    def reset_config(self, get=None):
        self._write_json(self._default_config())
        return self._reload()

    def test_rule(self, get):
        value = get.get("value", "")
        tests = {
            "sql": [r"union\s+select", r"sleep\s*\(", r"information_schema"],
            "xss": [r"<script", r"onerror\s*=", r"javascript:"],
            "command": [r";\s*(cat|bash|sh|wget|curl)", r"/bin/sh"],
            "sensitive_path": [r"\.\./", r"/etc/passwd", r"\.env"],
            "php_code": [r"eval\s*\(", r"base64_decode\s*\("],
            "weak_password": [r"password=123456", r"/phpmyadmin"],
            "upload": [r"\.(php|phtml|phar)($|\?)"],
            "bad_ua": [r"sqlmap", r"nikto", r"acunetix", r"nessus", r"masscan", r"zgrab"],
        }
        for category, rules in tests.items():
            for rule in rules:
                if re.search(rule, value, re.I):
                    return {"status": True, "blocked": True, "category": category, "rule": rule}
        return {"status": True, "blocked": False, "category": "", "rule": ""}
EOF
  cat > "$PLUGIN_DIR/index.html" <<'EOF'
<div class="local-waf-app">
  <style>
    html,body{overflow-x:hidden}
    .local-waf-app{display:flex;width:100%;height:100%;min-height:660px;color:#333;font-size:14px;overflow:hidden;box-sizing:border-box}
    .local-waf-menu{width:168px;background:#f3f5f7;padding:8px 0;flex:none}
    .local-waf-menu div{padding:12px 18px;cursor:pointer}
    .local-waf-menu .active{color:#20a53a;background:#fff;border-left:3px solid #20a53a}
    .local-waf-body{flex:1;min-width:0;padding:18px 22px;overflow-y:auto;overflow-x:hidden;box-sizing:border-box}
    .waf-card{border-bottom:1px solid #eee;padding:12px 0}
    .waf-toggle{font-weight:bold;font-size:16px}.waf-toggle input{width:18px;height:18px;vertical-align:middle;margin:0 6px}
    .waf-grid{display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:18px;margin-top:20px}
    .waf-stat{text-align:center;padding:18px 8px;border:1px solid #eee;background:#fff}
    .waf-stat b{display:block;font-size:28px;color:#20a53a;margin-top:8px;white-space:nowrap}
    .waf-table{width:100%;border-collapse:collapse;margin-top:10px;table-layout:fixed}
    .waf-table th{background:#f7f7f7;text-align:left}
    .waf-table th,.waf-table td{border-bottom:1px solid #eee;padding:10px 12px;vertical-align:middle;overflow:hidden;text-overflow:ellipsis}
    .waf-table .op{color:#20a53a;cursor:pointer;margin-right:12px}
    .waf-form-row{display:flex;border-bottom:1px solid #eee;padding:14px 0}
    .waf-form-label{width:150px;font-weight:bold}
    .waf-form-main{flex:1;min-width:0}
    .waf-form-desc{color:#777;margin-top:7px;line-height:22px}
    .waf-inline{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
    .waf-textarea{width:100%;height:260px;box-sizing:border-box;font-family:Consolas,monospace}
    .waf-toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
    .waf-region-table th:nth-child(1){width:230px}.waf-region-table th:nth-child(2){width:220px}.waf-region-table th:nth-child(3){width:90px}.waf-region-table th:nth-child(4){width:160px}.waf-region-table th:nth-child(5){width:80px}
    .waf-site-select{position:relative;width:420px;max-width:100%;margin:10px 0 12px}
    .waf-site-display{height:36px;border:1px solid #bbb;background:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 10px;cursor:pointer;box-sizing:border-box}
    .waf-site-display span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#666}
    .waf-site-select.open .waf-site-display{border-color:#20a53a;box-shadow:0 0 0 1px rgba(32,165,58,.15)}
    .waf-site-dropdown{display:none;position:absolute;left:0;top:40px;width:420px;max-width:calc(100vw - 80px);background:#fff;border:1px solid #ddd;box-shadow:0 3px 12px rgba(0,0,0,.14);z-index:50;padding:10px;box-sizing:border-box}
    .waf-site-select.open .waf-site-dropdown{display:block}
    .waf-site-bulk{display:grid;grid-template-columns:1fr 1fr;margin-bottom:8px;border:1px solid #ddd;border-radius:8px;overflow:hidden}
    .waf-site-bulk button{height:34px;border:0;background:#fff;cursor:pointer}.waf-site-bulk button+button{border-left:1px solid #ddd}
    .waf-site-list{max-height:210px;overflow:auto;margin-bottom:8px}
    .waf-site-item{display:flex;align-items:center;gap:8px;height:28px;line-height:28px;cursor:pointer;color:#333}
    .waf-site-item input{width:18px;height:18px;margin:0}.waf-site-ok{float:right;min-width:56px}
    .waf-region-summary{max-height:44px;line-height:22px;overflow:hidden;color:#666;margin:8px 0}
    .waf-region-grid{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:10px;margin-top:12px}
    .waf-region-item{border:1px solid #ddd;padding:10px 12px;min-height:48px;cursor:pointer;background:#fff;box-sizing:border-box}
    .waf-region-item.active{border-color:#20a53a;background:#effaf1;color:#20a53a}
    .waf-region-count{color:#888;margin-top:2px}.waf-region-tip{color:#777;margin:10px 0;line-height:22px}
    .waf-check{width:22px;height:22px}
    .waf-spider-table th:nth-child(1){width:150px}.waf-spider-table th:nth-child(2){width:260px}.waf-spider-table th:nth-child(3){width:210px}
    .waf-spider-policy{width:180px;height:34px}.waf-policy-note{color:#777;line-height:21px}.waf-verify-badge{display:inline-block;color:#1677ff;background:#eaf3ff;border-radius:3px;padding:2px 6px;margin-left:8px;font-size:12px}
    .waf-automation-hero{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;padding:16px 18px;background:#f7fbf8;border:1px solid #dceee0;margin-bottom:14px}
    .waf-automation-hero h3{margin:0 0 7px;font-size:17px}.waf-automation-hero p{margin:0;color:#666;line-height:22px}
    .waf-automation-table th:nth-child(1){width:190px}.waf-automation-table th:nth-child(2){width:260px}.waf-automation-table td:last-child{color:#666}
    .waf-tag{display:inline-block;padding:2px 7px;border-radius:3px;background:#effaf1;color:#20a53a;font-size:12px}
    @media(max-width:980px){.waf-grid{grid-template-columns:repeat(2,1fr)}.waf-region-grid{grid-template-columns:repeat(3,1fr)}}
  </style>
  <div class="local-waf-menu">
    <div data-tab="home" class="active">&#39318;&#39029;</div>
    <div data-tab="global">&#20840;&#23616;&#37197;&#32622;</div>
    <div data-tab="cc">&#38450;CC&#25915;&#20987;</div>
    <div data-tab="lists">&#40657;&#30333;&#21517;&#21333;</div>
    <div data-tab="spiders">&#x8718;&#x86DB;&#x7B56;&#x7565;</div>
    <div data-tab="automation">&#x81EA;&#x52A8;&#x5316;&#x9632;&#x62A4;</div>
    <div data-tab="region">&#22320;&#21306;&#38480;&#21046;</div>
    <div data-tab="filter">&#35775;&#38382;&#36807;&#28388;</div>
    <div data-tab="rules">&#32593;&#31449;&#28431;&#27934;&#38450;&#24481;</div>
    <div data-tab="log">&#25805;&#20316;&#26085;&#24535;</div>
    <div data-tab="config">&#37197;&#32622;&#22791;&#20221;</div>
  </div>
  <div class="local-waf-body">
    <div data-panel="home">
      <div class="waf-card"><div class="waf-inline"><label class="waf-toggle">&#38450;&#28779;&#22681;&#24320;&#20851; <input type="checkbox" id="waf-enabled" class="waf-switch"><span id="waf-enabled-text">&#20851;&#38381;</span></label><label class="waf-toggle" style="margin-left:28px">Cloudflare &#28304;&#31449;&#38145;&#23450; <input type="checkbox" id="cloudflare-origin-enabled" class="waf-switch"><span id="cloudflare-origin-text">&#20851;&#38381;</span></label></div><div class="waf-form-desc">&#24320;&#21551;&#21518;&#65292;80/443 &#20165;&#20801;&#35768; Cloudflare &#23448;&#26041; IP &#32593;&#27573;&#35775;&#38382;&#65292;SSH&#12289;&#38754;&#26495;&#31471;&#21475;&#21644;&#20854;&#20182;&#19994;&#21153;&#31471;&#21475;&#19981;&#21463;&#24433;&#21709;&#12290;</div></div>
      <div class="waf-grid">
        <div class="waf-stat">&#39118;&#38505;&#25318;&#25130;<b id="risk-total">0</b></div>
        <div class="waf-stat">&#23433;&#20840;&#20445;&#25252;<b id="safe-days">1&#22825;</b></div>
        <div class="waf-stat">SQL&#27880;&#20837;&#25318;&#25130;<b data-stat="sql">0</b></div>
        <div class="waf-stat">XSS&#25318;&#25130;<b data-stat="xss">0</b></div>
        <div class="waf-stat">CC&#25318;&#25130;<b data-stat="cc">0</b></div>
        <div class="waf-stat">&#24694;&#24847;&#25195;&#25551;&#25318;&#25130;<b data-stat="sensitive_path">0</b></div>
        <div class="waf-stat">&#21629;&#20196;&#25191;&#34892;&#25318;&#25130;<b data-stat="command">0</b></div>
        <div class="waf-stat">&#24694;&#24847;UA&#25318;&#25130;<b data-stat="bad_ua">0</b></div>
        <div class="waf-stat">&#x81EA;&#x52A8;&#x5316;&#x62E6;&#x622A;<b data-stat="automation">0</b></div>
      </div>
    </div>
    <div data-panel="global" style="display:none">
      <div class="waf-form-row"><div class="waf-form-label">&#21709;&#24212;&#29366;&#24577;&#30721;</div><div class="waf-form-main"><input id="response-code" class="bt-input-text" style="width:120px"><div class="waf-form-desc">&#25318;&#25130;&#35831;&#27714;&#36820;&#22238;&#30340; HTTP &#29366;&#24577;&#30721;&#65292;&#24120;&#29992; 403 &#25110; 444&#12290;</div></div></div>
      <div class="waf-form-row"><div class="waf-form-label">&#35268;&#21017;&#27979;&#35797;</div><div class="waf-form-main"><div class="waf-inline"><input id="test-value" class="bt-input-text" style="width:520px;max-width:100%" value="?id=1 union select password from users"><button class="btn btn-default btn-sm" id="test-rule">&#27979;&#35797;</button></div><div id="test-result" style="margin-top:8px"></div></div></div>
      <button class="btn btn-success btn-sm" id="save-global">&#20445;&#23384;&#20840;&#23616;&#37197;&#32622;</button>
    </div>
    <div data-panel="cc" style="display:none">
      <table class="waf-table"><thead><tr><th>&#21517;&#31216;</th><th>&#25551;&#36848;</th><th>&#29366;&#24577;</th></tr></thead><tbody>
        <tr><td>CC&#38450;&#24481;</td><td>&#36830;&#32493;&#35831;&#27714;&#36229;&#36807;&#38408;&#20540;&#26102;&#25318;&#25130;</td><td><input class="waf-check feature-check" data-feature="cc" type="checkbox"></td></tr>
        <tr><td>&#38745;&#24577;&#25991;&#20214;&#20445;&#25252;</td><td>&#23545;&#38745;&#24577;&#36164;&#28304;&#27969;&#37327;&#36827;&#34892;&#20445;&#25252;</td><td><input class="waf-check feature-check" data-feature="static" type="checkbox"></td></tr>
      </tbody></table>
      <div class="waf-form-row"><div class="waf-form-label">CC&#26102;&#38388;&#31383;</div><div class="waf-form-main"><input id="cc-window" class="bt-input-text" style="width:120px"> &#31186;</div></div>
      <div class="waf-form-row"><div class="waf-form-label">CC&#38408;&#20540;</div><div class="waf-form-main"><input id="cc-limit" class="bt-input-text" style="width:120px"> &#27425;</div></div>
      <div class="waf-form-row"><div class="waf-form-label">&#36335;&#24452;&#25195;&#25551;&#31383;&#21475;</div><div class="waf-form-main"><input id="scan-window" class="bt-input-text" style="width:120px"> &#31186;<div class="waf-form-desc">&#21516;&#19968; IP &#22312;&#35813;&#26102;&#38388;&#20869;&#35775;&#38382;&#22810;&#20010;&#19981;&#21516;&#36335;&#24452;&#26102;&#36827;&#34892;&#21028;&#23450;&#12290;</div></div></div>
      <div class="waf-form-row"><div class="waf-form-label">&#36335;&#24452;&#25195;&#25551;&#38408;&#20540;</div><div class="waf-form-main"><input id="scan-limit" class="bt-input-text" style="width:120px"> &#20010;&#19981;&#21516;&#36335;&#24452;</div></div>
      <div class="waf-form-row"><div class="waf-form-label">&#25195;&#25551;&#23553;&#38145;&#26102;&#38388;</div><div class="waf-form-main"><input id="scan-block-time" class="bt-input-text" style="width:120px"> &#31186;</div></div>
      <button class="btn btn-success btn-sm" id="save-cc">&#20445;&#23384;CC&#37197;&#32622;</button>
    </div>
    <div data-panel="lists" style="display:none">
      <div class="waf-toolbar">
        <button class="btn btn-default btn-sm list-btn" data-list="ip_whitelist">IP&#30333;&#21517;&#21333;</button>
        <button class="btn btn-default btn-sm list-btn" data-list="ip_blacklist">IP&#40657;&#21517;&#21333;</button>
        <button class="btn btn-default btn-sm list-btn" data-list="ua_whitelist">UA&#30333;&#21517;&#21333;</button>
        <button class="btn btn-default btn-sm list-btn" data-list="ua_blacklist">UA&#40657;&#21517;&#21333;</button>
        <button class="btn btn-default btn-sm list-btn" data-list="url_whitelist">URL&#30333;&#21517;&#21333;</button>
        <button class="btn btn-default btn-sm list-btn" data-list="url_blacklist">URL&#40657;&#21517;&#21333;</button>
      </div>
      <div id="list-title" style="font-weight:bold;margin-bottom:8px"></div>
      <textarea id="list-value" class="waf-textarea"></textarea>
      <div style="margin-top:10px"><button class="btn btn-success btn-sm" id="save-list">&#20445;&#23384;&#21517;&#21333;</button></div>
    </div>
    <div data-panel="spiders" style="display:none">
      <div class="waf-toolbar"><button class="btn btn-default btn-sm" id="spiders-allow-all">&#x5168;&#x90E8;&#x653E;&#x884C;</button><button class="btn btn-default btn-sm" id="spiders-block-all">&#x5168;&#x90E8;&#x5C4F;&#x853D;</button><button class="btn btn-success btn-sm" id="spiders-recommended">&#x6062;&#x590D;&#x63A8;&#x8350;&#x7B56;&#x7565;</button></div>
      <div class="waf-form-desc">&#x53EF;&#x6309;&#x8718;&#x86DB;&#x7C7B;&#x578B;&#x72EC;&#x7ACB;&#x653E;&#x884C;&#x6216;&#x5C4F;&#x853D;&#x3002;Google&#x3001;Bing&#x548C;&#x767E;&#x5EA6;&#x53EF;&#x9009;&#x62E9;&#x201C;&#x5B98;&#x65B9; IP &#x9A8C;&#x8BC1;&#x540E;&#x653E;&#x884C;&#x201D;&#xFF0C;&#x963B;&#x6B62;&#x4EC5;&#x4F2A;&#x9020; UA &#x7684;&#x5047;&#x8718;&#x86DB;&#x3002;IP/URL/UA &#x9ED1;&#x540D;&#x5355;&#x548C;&#x5730;&#x533A;&#x89C4;&#x5219;&#x4ECD;&#x4F18;&#x5148;&#x751F;&#x6548;&#x3002;</div>
      <table class="waf-table waf-spider-table"><thead><tr><th>&#x8718;&#x86DB;&#x7C7B;&#x578B;</th><th>UA &#x8BC6;&#x522B;&#x7279;&#x5F81;</th><th>&#x5904;&#x7406;&#x7B56;&#x7565;</th><th>&#x8BF4;&#x660E;</th></tr></thead><tbody id="spider-table"></tbody></table>
    </div>
    <div data-panel="automation" style="display:none">
      <div class="waf-automation-hero">
        <div><h3>&#x4F2A;&#x88C5;&#x666E;&#x901A;&#x6D4F;&#x89C8;&#x5668;&#x7684;&#x81EA;&#x52A8;&#x5316;&#x6D41;&#x91CF;</h3><p>&#x8054;&#x5408;&#x5224;&#x65AD;&#x6D4F;&#x89C8;&#x5668;&#x8BF7;&#x6C42;&#x5934;&#x3001;&#x77ED;&#x65F6;&#x8BF7;&#x6C42;&#x901F;&#x7387;&#x548C;&#x8DEF;&#x5F84;&#x79BB;&#x6563;&#x5EA6;&#x3002;&#x5355;&#x4E2A;&#x8BF7;&#x6C42;&#x5934;&#x7F3A;&#x5931;&#x4E0D;&#x4F1A;&#x89E6;&#x53D1;&#x62E6;&#x622A;&#x3002;</p></div>
        <label class="waf-toggle"><input type="checkbox" class="waf-switch feature-check" data-feature="automation">&#x542F;&#x7528;&#x9632;&#x62A4;</label>
      </div>
      <div class="waf-form-row"><div class="waf-form-label">&#x68C0;&#x6D4B;&#x7A97;&#x53E3;</div><div class="waf-form-main"><input id="automation-window" class="bt-input-text" style="width:120px"> &#x79D2;<div class="waf-form-desc">&#x4EE5;&#x771F;&#x5B9E;&#x5BA2;&#x6237;&#x7AEF; IP + &#x7AD9;&#x70B9;&#x72EC;&#x7ACB;&#x7EDF;&#x8BA1;&#x3002;</div></div></div>
      <div class="waf-form-row"><div class="waf-form-label">&#x9875;&#x9762;&#x8BF7;&#x6C42;&#x4E0A;&#x9650;</div><div class="waf-form-main"><input id="automation-limit" class="bt-input-text" style="width:120px"> &#x6B21;<div class="waf-form-desc">&#x8D85;&#x8FC7;&#x9608;&#x503C;&#x624D;&#x6309;&#x6D4F;&#x89C8;&#x5668;&#x6D2A;&#x6CDB;&#x5904;&#x7406;&#xFF0C;CSS/JS/&#x56FE;&#x7247;&#x7B49;&#x9759;&#x6001;&#x8D44;&#x6E90;&#x4E0D;&#x8BA1;&#x5165;&#x3002;</div></div></div>
      <div class="waf-form-row"><div class="waf-form-label">&#x4E0D;&#x540C;&#x8DEF;&#x5F84;&#x4E0A;&#x9650;</div><div class="waf-form-main"><input id="automation-distinct-limit" class="bt-input-text" style="width:120px"> &#x4E2A;<div class="waf-form-desc">&#x914D;&#x5408;&#x8BF7;&#x6C42;&#x5934;&#x5F02;&#x5E38;&#x5206;&#x6570;&#x8BC6;&#x522B;&#x6279;&#x91CF;&#x679A;&#x4E3E;&#x9875;&#x9762;&#x3002;</div></div></div>
      <div class="waf-form-row"><div class="waf-form-label">&#x8DE8; IP &#x6307;&#x7EB9;&#x8BF7;&#x6C42;&#x4E0A;&#x9650;</div><div class="waf-form-main"><input id="automation-distributed-limit" class="bt-input-text" style="width:120px"> &#x6B21;<div class="waf-form-desc">&#x540C;&#x4E00;&#x6D4F;&#x89C8;&#x5668;&#x6307;&#x7EB9;&#x5728;&#x591A;&#x4E2A; IP &#x95F4;&#x540C;&#x65F6;&#x679A;&#x4E3E;&#x9875;&#x9762;&#x65F6;&#x89E6;&#x53D1;&#x3002;</div></div></div>
      <div class="waf-form-row"><div class="waf-form-label">&#x8DE8; IP &#x6765;&#x6E90;&#x4E0A;&#x9650;</div><div class="waf-form-main"><input id="automation-distributed-ip-limit" class="bt-input-text" style="width:120px"> &#x4E2A;<div class="waf-form-desc">&#x53EA;&#x6709;&#x540C;&#x6307;&#x7EB9;&#x6765;&#x81EA;&#x8DB3;&#x591F;&#x591A;&#x4E0D;&#x540C; IP &#x624D;&#x4F1A;&#x6309;&#x5206;&#x5E03;&#x5F0F;&#x81EA;&#x52A8;&#x5316;&#x5904;&#x7406;&#x3002;</div></div></div>
      <div class="waf-form-row"><div class="waf-form-label">&#x4E34;&#x65F6;&#x5C01;&#x9501;&#x65F6;&#x95F4;</div><div class="waf-form-main"><input id="automation-block-time" class="bt-input-text" style="width:120px"> &#x79D2;</div></div>
      <button class="btn btn-success btn-sm" id="save-automation">&#x4FDD;&#x5B58;&#x81EA;&#x52A8;&#x5316;&#x9632;&#x62A4;&#x914D;&#x7F6E;</button>
      <table class="waf-table waf-automation-table" style="margin-top:18px"><thead><tr><th>&#x68C0;&#x6D4B;&#x7EF4;&#x5EA6;</th><th>&#x89E6;&#x53D1;&#x65B9;&#x5F0F;</th><th>&#x8BEF;&#x62A5;&#x4FDD;&#x62A4;</th></tr></thead><tbody>
        <tr><td>&#x660E;&#x786E;&#x81EA;&#x52A8;&#x5316;&#x6807;&#x8BC6;</td><td>HeadlessChrome / Selenium / Playwright / Puppeteer &#x7B49;</td><td><span class="waf-tag">&#x7ACB;&#x5373;&#x62E6;&#x622A;</span></td></tr>
        <tr><td>&#x6D4F;&#x89C8;&#x5668;&#x5934;&#x4E00;&#x81F4;&#x6027;</td><td>Sec-Fetch&#x3001;Accept-Language&#x3001;Sec-CH-UA &#x7B49;&#x8054;&#x5408;&#x8BC4;&#x5206;</td><td>&#x5C11;&#x4E00;&#x4E2A;&#x5934;&#x4E0D;&#x4F1A;&#x5355;&#x72EC;&#x62E6;&#x622A;</td></tr>
        <tr><td>&#x8BF7;&#x6C42;&#x884C;&#x4E3A;</td><td>&#x77ED;&#x65F6;&#x9AD8;&#x9891;&#x6216;&#x6279;&#x91CF;&#x679A;&#x4E3E;&#x4E0D;&#x540C;&#x9875;&#x9762;</td><td>&#x5355; IP &#x548C;&#x8DE8; IP &#x540C;&#x6307;&#x7EB9;&#x5206;&#x5C42;&#x7EDF;&#x8BA1;</td></tr>
        <tr><td>&#x81EA;&#x52A8;&#x653E;&#x884C;</td><td>&#x771F;&#x5B9E;&#x641C;&#x7D22;&#x8718;&#x86DB;&#x3001;&#x641C;&#x7D22;&#x7ED3;&#x679C;&#x6765;&#x6E90;&#x3001;&#x9759;&#x6001;&#x8D44;&#x6E90;</td><td><span class="waf-tag">&#x4E0D;&#x9650;&#x5236;</span></td></tr>
      </tbody></table>
    </div>
    <div data-panel="region" style="display:none">
      <div class="waf-toolbar"><button class="btn btn-success btn-sm" id="add-region">&#28155;&#21152;&#22320;&#21306;&#38480;&#21046;</button><button class="btn btn-default btn-sm" id="sync-region">&#21516;&#27493;&#22320;&#21306;IP&#24211;</button><select id="region-mode" class="bt-input-text" style="width:140px"><option value="block">&#25318;&#25130;</option><option value="allow">&#21482;&#25918;&#34892;</option></select><span id="region-sync-state"></span></div>
      <table class="waf-table waf-region-table"><thead><tr><th>&#22320;&#21306;</th><th>&#31449;&#28857;</th><th>&#31867;&#22411;</th><th>IP&#24211;</th><th>&#25805;&#20316;</th></tr></thead><tbody id="region-rules"></tbody></table>
      <div class="waf-region-tip">&#20808;&#22312;&#19979;&#38754;&#36873;&#25321;&#22320;&#21306;&#21644;&#31449;&#28857;&#65292;&#20877;&#28857;&#20987;&#8220;&#28155;&#21152;&#22320;&#21306;&#38480;&#21046;&#8221;&#12290;&#26412;&#26426;/&#31169;&#32593; IP &#40664;&#35748;&#25918;&#34892;&#12290;</div>
      <h4>&#20316;&#29992;&#31449;&#28857;</h4>
      <div class="waf-site-select" id="site-select"><div class="waf-site-display"><span id="site-selected-text">&#20840;&#37096;&#31449;&#28857;</span><span>&#9662;</span></div><div class="waf-site-dropdown"><div class="waf-site-bulk"><button type="button" id="site-all">&#20840;&#36873;</button><button type="button" id="site-none">&#21462;&#28040;&#20840;&#36873;</button></div><div class="waf-site-list" id="site-list"></div><button type="button" class="btn btn-success btn-sm waf-site-ok" id="site-ok">&#30830;&#23450;</button></div></div>
      <div class="waf-region-summary" id="region-selected-summary"></div>
      <div class="waf-region-grid" id="region-grid"></div>
    </div>
    <div data-panel="filter" style="display:none">
      <table class="waf-table"><thead><tr><th>&#21517;&#31216;</th><th>&#25551;&#36848;</th><th>&#29366;&#24577;</th></tr></thead><tbody>
        <tr><td>&#24694;&#24847;&#24037;&#20855; UA &#25318;&#25130;</td><td>&#21482;&#25318;&#25130;&#26126;&#30830;&#28431;&#27934;&#25195;&#25551;&#22120;&#21644;&#25915;&#20987;&#24037;&#20855; UA</td><td><input class="waf-check feature-check" data-feature="bad_ua" type="checkbox"></td></tr>
        <tr><td>HTTP&#35831;&#27714;&#31867;&#22411;&#36807;&#28388;</td><td>&#25318;&#25130;TRACE&#31561;&#21361;&#38505;&#26041;&#27861;</td><td><input class="waf-check feature-check" data-feature="method" type="checkbox"></td></tr>
        <tr><td>&#31105;&#27490;&#22269;&#22806;&#35775;&#38382;</td><td>&#38656;&#20808;&#21516;&#27493;&#20013;&#22269;&#22823;&#38470;IP&#24211;</td><td><input class="waf-check feature-check" data-feature="block_foreign" type="checkbox"></td></tr>
      </tbody></table>
    </div>
    <div data-panel="rules" style="display:none">
      <table class="waf-table"><thead><tr><th>&#21517;&#31216;</th><th>&#25551;&#36848;</th><th>&#21709;&#24212;</th><th>&#29366;&#24577;</th></tr></thead><tbody id="rule-table"></tbody></table>
    </div>
    <div data-panel="log" style="display:none"><pre id="waf-log" style="background:#111;color:#ddd;padding:12px;min-height:420px;white-space:pre-wrap;overflow:auto"></pre><button class="btn btn-default btn-sm" id="clear-log">&#28165;&#31354;&#26085;&#24535;</button></div>
    <div data-panel="config" style="display:none"><textarea id="config-json" class="waf-textarea"></textarea><div style="margin-top:10px"><button class="btn btn-success btn-sm" id="import-config">&#23548;&#20837;&#37197;&#32622;</button><button class="btn btn-default btn-sm" id="reset-config">&#24674;&#22797;&#40664;&#35748;</button></div></div>
  </div>
</div>
<script type="text/javascript">
(function(){
  var cfg={}, countries={}, syncedRegions={}, siteList=[], currentList='ip_whitelist';
  var selectedRegions=[], selectedSites=[];
  var SPIDER_DEFS=[
    ['google','Google','Googlebot / Storebot-Google / Google-InspectionTool',true],
    ['bing','Bing','bingbot / BingPreview / adidxbot',true],
    ['baidu','\u767e\u5ea6','Baiduspider',true],
    ['sogou','\u641c\u72d7','Sogou',false],
    ['360','360','360Spider / HaosouSpider',false],
    ['shenma','\u795e\u9a6c','YisouSpider / Shenma',false],
    ['duckduckgo','DuckDuckGo','DuckDuckBot',false],
    ['yandex','Yandex','YandexBot',false],
    ['apple','Apple','Applebot',false],
    ['bytespider','\u5b57\u8282','Bytespider',false],
    ['petal','Petal','PetalBot',false],
    ['yahoo','Yahoo','Slurp / YahooSeeker',false],
    ['seo_tools','SEO \u5de5\u5177','SemrushBot / AhrefsBot / MJ12Bot / DotBot / BLEXBot',false],
    ['other','\u5176\u4ed6\u8718\u86db','\u5176\u4ed6\u542b bot / crawler / spider \u7684 UA',false]
  ];
  var RECOMMENDED_SPIDERS={google:'verify',bing:'verify',baidu:'verify',sogou:'allow','360':'allow',shenma:'allow',duckduckgo:'allow',yandex:'allow',apple:'allow',bytespider:'allow',petal:'allow',yahoo:'allow',seo_tools:'block',other:'allow'};
  var REGION_ORDER=['CN','HK','MO','TW','US','GB','AU','CA','NZ','RU','UA','BY','DE','FR','JP','KR','SG','MY','NO','SE','FI','IE','NL','DK','IT','ES'];
  var REGION_NAMES={CN:'\u4e2d\u56fd\u5927\u9646',HK:'\u4e2d\u56fd\u9999\u6e2f',MO:'\u4e2d\u56fd\u6fb3\u95e8',TW:'\u4e2d\u56fd\u53f0\u6e7e',US:'\u7f8e\u56fd',GB:'\u82f1\u56fd',AU:'\u6fb3\u5927\u5229\u4e9a',CA:'\u52a0\u62ff\u5927',NZ:'\u65b0\u897f\u5170',RU:'\u4fc4\u7f57\u65af',UA:'\u4e4c\u514b\u5170',BY:'\u767d\u4fc4\u7f57\u65af',DE:'\u5fb7\u56fd',FR:'\u6cd5\u56fd',JP:'\u65e5\u672c',KR:'\u97e9\u56fd',SG:'\u65b0\u52a0\u5761',MY:'\u9a6c\u6765\u897f\u4e9a',NO:'\u632a\u5a01',SE:'\u745e\u5178',FI:'\u82ac\u5170',IE:'\u7231\u5c14\u5170',NL:'\u8377\u5170',DK:'\u4e39\u9ea6',IT:'\u610f\u5927\u5229',ES:'\u897f\u73ed\u7259'};
  function notifyPluginLoaded(){try{if(parent&&parent!==window)parent.postMessage('pluginLoad','*'); if(parent&&parent.parent&&parent.parent!==parent)parent.parent.postMessage('pluginLoad','*')}catch(e){}}
  notifyPluginLoaded();
  function fitDialog(){try{var win=parent&&parent!==window?parent.window:window, jq=parent&&parent.$?parent.$:$, ww=win.innerWidth||1200, hh=win.innerHeight||760, width=Math.min(1180,Math.max(1040,ww-80)), height=Math.min(800,Math.max(700,hh-70)), box=jq('.local-waf-app').closest('.layui-layer'); if((!box||!box.length)&&parent&&parent.$){var frame=parent.$('iframe').filter(function(){return this.contentWindow===window}); box=frame.closest('.layui-layer'); frame.css({width:'100%',height:'100%'})} if(box&&box.length){box.css({width:width+'px',height:height+'px',left:Math.max(20,Math.floor((ww-width)/2))+'px',maxWidth:'calc(100vw - 40px)'}); box.find('.layui-layer-content').css({width:'100%',height:(height-44)+'px',overflow:'hidden'}); box.find('iframe').css({width:'100%',height:'100%'})}}catch(e){}}
  fitDialog(); setTimeout(fitDialog,80); setTimeout(fitDialog,300);
  function unwrap(r){for(var i=0;i<5;i++){if(typeof r==='string'){try{r=JSON.parse(r)}catch(e){return {status:false,msg:r||'error'}}} if(r&&r.status===true&&r.msg&&typeof r.msg==='object'){r=r.msg;continue} if(r&&r.status===true&&r.data&&typeof r.data==='object'){r=r.data;continue} break} return r||{}}
  function post(s,data,ok){$.ajax({url:'/plugin?action=a&name=local_waf&s='+s,type:'POST',data:data||{},headers:{'x-http-token':window.vite_public_request_token||$('#request_token_head').attr('token')||''},success:function(r){r=unwrap(r); if(r&&r.status===false){layer.msg(r.msg||'error',{icon:2});return} ok&&ok(r||{})},error:function(){layer.msg('request failed',{icon:2})}})}
  function regionName(c){return (REGION_NAMES[c]||countries[c]||c)+' ('+c+')'}
  function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
  function setChecks(features){features=features||{}; $('[data-feature]').each(function(){var k=$(this).data('feature'); $(this).prop('checked', typeof features[k]==='undefined'?true:!!features[k])})}
  function renderRuleTable(){var items=[['sql','SQL\u6ce8\u5165\u9632\u5fa1','\u68c0\u6d4b\u6076\u610fSQL\u8bed\u53e5'],['xss','XSS\u9632\u5fa1','\u68c0\u6d4b\u811a\u672c\u6ce8\u5165'],['command','\u547d\u4ee4\u6267\u884c\u62e6\u622a','\u62e6\u622a\u5371\u9669\u547d\u4ee4\u6267\u884c\u7279\u5f81'],['weak_password','\u5f31\u5bc6\u7801\u9632\u5fa1','\u62e6\u622a\u660e\u663e\u5f31\u53e3\u4ee4\u63a2\u6d4b'],['sensitive_path','\u6076\u610f\u626b\u63cf\u62e6\u622a','\u62e6\u622a\u654f\u611f\u6587\u4ef6\u548c\u76ee\u5f55\u7a7f\u8d8a'],['php_code','PHP\u4ee3\u7801\u62e6\u622a','\u62e6\u622a\u5e38\u89c1WebShell\u51fd\u6570\u7279\u5f81'],['upload','\u6587\u4ef6\u4e0a\u4f20\u62e6\u622a','\u62e6\u622a\u5371\u9669\u811a\u672c\u6269\u5c55\u4e0a\u4f20']]; var h=''; $.each(items,function(_,x){h+='<tr><td>'+x[1]+'</td><td>'+x[2]+'</td><td class=\"resp-code\">'+(cfg.response_code||403)+'</td><td><input class=\"waf-check feature-check\" data-feature=\"'+x[0]+'\" type=\"checkbox\"></td></tr>'}); $('#rule-table').html(h); setChecks(cfg.features)}
  function renderSpiderPolicies(){cfg.spiders=$.extend({},RECOMMENDED_SPIDERS,cfg.spiders||{}); var h=''; $.each(SPIDER_DEFS,function(_,x){var key=x[0],verify=x[3],policy=cfg.spiders[key]||'allow',options='<option value="allow">\u653e\u884c</option>'; if(verify) options+='<option value="verify">\u5b98\u65b9 IP \u9a8c\u8bc1\u540e\u653e\u884c</option>'; options+='<option value="block">\u5c4f\u853d</option>'; var note=verify?'\u53ef\u9a8c\u8bc1\u5b98\u65b9 IP \u6bb5<span class="waf-verify-badge">IP \u9a8c\u8bc1</span>':'\u6309 UA \u7c7b\u578b\u8bc6\u522b'; h+='<tr><td>'+esc(x[1])+'</td><td>'+esc(x[2])+'</td><td><select class="bt-input-text waf-spider-policy" data-spider="'+key+'">'+options+'</select></td><td class="waf-policy-note">'+note+'</td></tr>'}); $('#spider-table').html(h); $('.waf-spider-policy').each(function(){$(this).val(cfg.spiders[$(this).data('spider')]||'allow')})}
  function renderSites(){var list=siteList||[], html=''; $.each(list,function(_,s){var checked=selectedSites.indexOf(s)>=0?' checked':''; html+='<label class=\"waf-site-item\"><input type=\"checkbox\" value=\"'+esc(s)+'\"'+checked+'> <span>'+esc(s)+'</span></label>'}); if(!html) html='<div style=\"color:#999;padding:8px\">no sites</div>'; $('#site-list').html(html); updateSiteText()}
  function updateSiteText(){var text=selectedSites.length?selectedSites.join(', '):'\u5168\u90e8\u7ad9\u70b9'; $('#site-selected-text').text(text)}
  function renderRegions(){var html=''; $.each(REGION_ORDER,function(_,c){var sync=syncedRegions[c], count=sync&&sync.count?sync.count:0, active=selectedRegions.indexOf(c)>=0?' active':''; html+='<div class=\"waf-region-item'+active+'\" data-code=\"'+c+'\"><div>'+regionName(c)+'</div><div class=\"waf-region-count\">'+(count?count+'\u6bb5':'')+'</div></div>'}); $('#region-grid').html(html); refreshRegionSummary()}
  function refreshRegionSummary(){var text=selectedRegions.length?selectedRegions.map(regionName).join(', '):'\u672a\u9009\u62e9\u5730\u533a'; $('#region-selected-summary').text(text)}
  function regionRules(){var region=(cfg&&cfg.region)||{}, rules=region.rules||[]; if(!rules.length&&region.countries&&region.countries.length) rules=[{id:'legacy',mode:region.mode||'block',countries:region.countries,sites:region.sites||[]}]; return rules}
  function renderRegionRules(){var rows='', rules=regionRules(); $.each(rules,function(i,r){var cs=(r.countries||[]).map(regionName).join(', '), ss=(r.sites&&r.sites.length)?r.sites.join(', '):'\u5168\u90e8\u7ad9\u70b9', counts=(r.countries||[]).map(function(c){var s=syncedRegions[c]; return c+':'+(s&&s.count?s.count+'\u6bb5':'\u672a\u540c\u6b65')}).join(', '); rows+='<tr><td title=\"'+esc(cs)+'\">'+esc(cs)+'</td><td title=\"'+esc(ss)+'\">'+esc(ss)+'</td><td>'+(r.mode==='allow'?'\u53ea\u653e\u884c':'\u62e6\u622a')+'</td><td title=\"'+esc(counts)+'\">'+esc(counts)+'</td><td><span class=\"op del-region\" data-id=\"'+esc(r.id||'')+'\" data-index=\"'+i+'\">\u5220\u9664</span></td></tr>'}); $('#region-rules').html(rows||'<tr><td colspan=\"5\" style=\"text-align:center;color:#999\">\u6682\u65e0\u5730\u533a\u89c4\u5219</td></tr>'); $('#region-sync-state').text(rules.length?('\u5171 '+rules.length+' \u6761\u89c4\u5219'):'\u672a\u6dfb\u52a0\u89c4\u5219')}
  function showList(key, activate){currentList=key; $('#list-title').text(key); $('#list-value').val(((cfg.lists||{})[key]||[]).join('\n')); if(activate!==false) $('.local-waf-menu [data-tab=\"lists\"]').click()}
  function load(){post('get_status',{},function(r){notifyPluginLoaded(); cfg=r.config||{}; cfg.features=cfg.features||{}; cfg.lists=cfg.lists||{}; cfg.spiders=$.extend({},RECOMMENDED_SPIDERS,cfg.spiders||{}); countries=r.countries||{}; syncedRegions=r.synced_regions||{}; siteList=r.sites||[]; $('#waf-enabled').prop('checked',!!r.enabled); $('#waf-enabled-text').text(r.enabled?'\u5df2\u5f00\u542f':'\u5173\u95ed'); var cf=r.cloudflare_origin||{}; $('#cloudflare-origin-enabled').prop('checked',!!cf.enabled).prop('disabled',cf.available===false); $('#cloudflare-origin-text').text(cf.enabled?'\u5df2\u9501\u5b9a':'\u5173\u95ed'); $('#risk-total').text(r.risk_total||0); $('#safe-days').text((r.safe_days||1)+'\u5929'); $('[data-stat]').each(function(){$(this).text((r.stats||{})[$(this).data('stat')]||0)}); $('#response-code').val(cfg.response_code||403); $('#cc-window').val(cfg.cc_window||10); $('#cc-limit').val(cfg.cc_limit||60); $('#scan-window').val(cfg.scan_window||10); $('#scan-limit').val(cfg.scan_limit||6); $('#scan-block-time').val(cfg.scan_block_time||60); $('#automation-window').val(cfg.automation_window||10); $('#automation-limit').val(cfg.automation_limit||120); $('#automation-distinct-limit').val(cfg.automation_distinct_limit||24); $('#automation-distributed-limit').val(cfg.automation_distributed_limit||80); $('#automation-distributed-ip-limit').val(cfg.automation_distributed_ip_limit||12); $('#automation-block-time').val(cfg.automation_block_time||300); $('.resp-code').text(cfg.response_code||403); setChecks(cfg.features); renderRuleTable(); renderSpiderPolicies(); $('#waf-log').text(r.log||'\u6682\u65e0\u62e6\u622a\u65e5\u5fd7'); $('#config-json').val(JSON.stringify(cfg,null,2)); renderSites(); renderRegions(); renderRegionRules(); showList(currentList,false)})}
  function saveConfig(done){cfg.response_code=parseInt($('#response-code').val()||403,10); cfg.cc_window=parseInt($('#cc-window').val()||10,10); cfg.cc_limit=parseInt($('#cc-limit').val()||60,10); cfg.scan_window=parseInt($('#scan-window').val()||10,10); cfg.scan_limit=parseInt($('#scan-limit').val()||6,10); cfg.scan_block_time=parseInt($('#scan-block-time').val()||60,10); cfg.automation_window=parseInt($('#automation-window').val()||10,10); cfg.automation_limit=parseInt($('#automation-limit').val()||120,10); cfg.automation_distinct_limit=parseInt($('#automation-distinct-limit').val()||24,10); cfg.automation_distributed_limit=parseInt($('#automation-distributed-limit').val()||80,10); cfg.automation_distributed_ip_limit=parseInt($('#automation-distributed-ip-limit').val()||12,10); cfg.automation_block_time=parseInt($('#automation-block-time').val()||300,10); post('save_config',{config:JSON.stringify(cfg)},function(){layer.msg('\u5df2\u4fdd\u5b58',{icon:1}); load(); done&&done()})}
  $('.local-waf-menu div').click(function(){var tab=$(this).data('tab'); $('.local-waf-menu div').removeClass('active'); $(this).addClass('active'); $('[data-panel]').hide(); $('[data-panel=\"'+tab+'\"]').show(); fitDialog()});
  $('#waf-enabled').change(function(){var on=$(this).is(':checked')?1:0; post('set_enable',{enabled:on},function(){layer.msg('\u5df2\u5207\u6362',{icon:1}); load()})});
  $('#cloudflare-origin-enabled').change(function(){var el=$(this),on=el.is(':checked')?1:0; el.prop('disabled',true); post('set_cloudflare_origin',{enabled:on},function(){layer.msg(on?'Cloudflare \u6e90\u7ad9\u9501\u5b9a\u5df2\u5f00\u542f':'Cloudflare \u6e90\u7ad9\u9501\u5b9a\u5df2\u5173\u95ed',{icon:1}); load()})});
  $(document).on('change','.feature-check',function(){post('set_feature',{key:$(this).data('feature'),enabled:$(this).is(':checked')?1:0},function(){layer.msg('\u5df2\u4fdd\u5b58',{icon:1}); load()})});
  $('#save-global,#save-cc,#save-automation').click(function(){saveConfig()});
  $('.list-btn').click(function(){showList($(this).data('list'))}); $('#save-list').click(function(){post('save_list',{key:currentList,value:$('#list-value').val()},function(){layer.msg('\u5df2\u4fdd\u5b58',{icon:1}); load()})});
  $(document).on('change','.waf-spider-policy',function(){var key=$(this).data('spider'),policy=$(this).val(); post('set_spider_policy',{key:key,policy:policy},function(){layer.msg('\u8718\u86db\u7b56\u7565\u5df2\u4fdd\u5b58',{icon:1}); load()})});
  $('#spiders-allow-all').click(function(){cfg.spiders=cfg.spiders||{}; $.each(SPIDER_DEFS,function(_,x){cfg.spiders[x[0]]='allow'}); saveConfig()});
  $('#spiders-block-all').click(function(){cfg.spiders=cfg.spiders||{}; $.each(SPIDER_DEFS,function(_,x){cfg.spiders[x[0]]='block'}); saveConfig()});
  $('#spiders-recommended').click(function(){cfg.spiders=$.extend({},RECOMMENDED_SPIDERS); saveConfig()});
  $('#site-select .waf-site-display').click(function(){$('#site-select').toggleClass('open')}); $('#site-ok').click(function(){$('#site-select').removeClass('open')}); $('#site-all').click(function(){selectedSites=(siteList||[]).slice(); renderSites()}); $('#site-none').click(function(){selectedSites=[]; renderSites()}); $(document).on('change','#site-list input',function(){var v=$(this).val(); if(this.checked&&selectedSites.indexOf(v)<0) selectedSites.push(v); if(!this.checked) selectedSites=$.grep(selectedSites,function(x){return x!==v}); updateSiteText()});
  $(document).on('click','.waf-region-item',function(){var c=$(this).data('code'); if(selectedRegions.indexOf(c)>=0) selectedRegions=$.grep(selectedRegions,function(x){return x!==c}); else selectedRegions.push(c); renderRegions()});
  $('#add-region').click(function(){if(!selectedRegions.length){layer.msg('\u8bf7\u5148\u9009\u62e9\u5730\u533a',{icon:2});return} post('save_region',{mode:$('#region-mode').val(),countries:JSON.stringify(selectedRegions),sites:JSON.stringify(selectedSites)},function(r){layer.msg('\u5df2\u6dfb\u52a0',{icon:1}); selectedRegions=[]; load()})});
  $(document).on('click','.del-region',function(){post('delete_region',{id:$(this).data('id'),index:$(this).data('index')},function(){layer.msg('\u5df2\u5220\u9664',{icon:1}); load()})});
  $('#sync-region').click(function(){var codes=[]; $.each(regionRules(),function(_,r){$.each(r.countries||[],function(_,c){if(codes.indexOf(c)<0) codes.push(c)})}); if(!codes.length) codes=selectedRegions.slice(); if(!codes.length){layer.msg('\u8bf7\u5148\u6dfb\u52a0\u6216\u9009\u62e9\u5730\u533a',{icon:2});return} $('#region-sync-state').text('\u540c\u6b65\u4e2d...'); post('sync_region',{countries:JSON.stringify(codes)},function(r){syncedRegions=$.extend(syncedRegions,r.synced||{}); var fail=(r.fail||[]).length; layer.msg(fail?('\u90e8\u5206\u5931\u8d25: '+r.fail.join(',')):'\u540c\u6b65\u5b8c\u6210',{icon:fail?2:1}); load()})});
  $('#test-rule').click(function(){post('test_rule',{value:$('#test-value').val()},function(r){$('#test-result').text(r.blocked?('\u4f1a\u62e6\u622a: '+r.category+' / '+r.rule):'\u4e0d\u4f1a\u62e6\u622a').css('color',r.blocked?'#d9534f':'#20a53a')})});
  $('#clear-log').click(function(){post('clear_log',{},function(){layer.msg('\u5df2\u6e05\u7a7a',{icon:1}); load()})}); $('#import-config').click(function(){post('import_config',{config:$('#config-json').val()},function(){layer.msg('\u5df2\u5bfc\u5165',{icon:1}); load()})}); $('#reset-config').click(function(){post('reset_config',{},function(){layer.msg('\u5df2\u6062\u590d',{icon:1}); load()})});
  load();
})();
</script>
EOF
}

migrate_config() {
  python3 - "$WAF_DIR/config.json" <<'PY'
import json
import os
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as handle:
        config = json.load(handle)
except Exception:
    config = {}

defaults = {
    "automation_window": 10,
    "automation_limit": 120,
    "automation_distinct_limit": 24,
    "automation_distributed_limit": 80,
    "automation_distributed_ip_limit": 12,
    "automation_block_time": 300,
}
for key, value in defaults.items():
    config.setdefault(key, value)
config.setdefault("features", {}).setdefault("automation", True)

tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(config, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
os.replace(tmp, path)
PY
}

insert_include() {
  python3 - "$NGINX_CONF" "$INCLUDE_LINE" <<'PY'
import sys
path, line = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8", errors="ignore").read()
if line.strip() in text:
    sys.exit(0)
idx = text.find("http")
brace = text.find("{", idx)
if idx == -1 or brace == -1:
    raise SystemExit("nginx.conf has no http block")
text = text[:brace+1] + "\n" + line + text[brace+1:]
open(path, "w", encoding="utf-8").write(text)
PY
}

remove_include() {
  python3 - "$NGINX_CONF" "$INCLUDE_LINE" <<'PY'
import sys
path, line = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8", errors="ignore").read()
text = text.replace("\n" + line, "").replace(line + "\n", "")
open(path, "w", encoding="utf-8").write(text)
PY
}

neutralize_legacy_darkjump_waf() {
  local proxy_conf="/www/server/nginx/conf/proxy.conf"
  local legacy_waf="/www/server/nginx/html/waf.lua"
  local quarantine="/root/bt-clean-quarantine-$(date +%Y%m%d_%H%M%S)"
  local legacy_lua_re='^[[:space:]]*(access|body_filter|header_filter)_by_lua_file[[:space:]]+/www/server/nginx/html/waf\.lua;[[:space:]]*$'
  local detected=0

  [ -f "$proxy_conf" ] && grep -qE "$legacy_lua_re" "$proxy_conf" && detected=1
  [ -e "$legacy_waf" ] && detected=1
  if [ -f "$proxy_conf" ]; then
    chattr -i -a "$proxy_conf" >/dev/null 2>&1 || true
    sed -i '/^[[:space:]]*lua_shared_dict[[:space:]]\+my_cache[[:space:]]\+10m;[[:space:]]*$/d' "$proxy_conf"
  fi
  if [ "$detected" -eq 1 ]; then
    mkdir -p "$quarantine"
    chattr -i -a "$proxy_conf" "$legacy_waf" >/dev/null 2>&1 || true
    [ -f "$legacy_waf" ] && sha256sum "$legacy_waf" 2>/dev/null | awk '{print $1 "  removed_darkjump_payload"}' > "$quarantine/REMOVED_SHA256SUMS" || true
    sed -E -i '\#^[[:space:]]*(access|body_filter|header_filter)_by_lua_file[[:space:]]+/www/server/nginx/html/waf\.lua;[[:space:]]*$#d' "$proxy_conf"
    [ -f "$legacy_waf" ] && { shred -u "$legacy_waf" 2>/dev/null || rm -f "$legacy_waf"; }
    echo "legacy injected waf quarantined: $quarantine"
  fi
  find /www/server/nginx/conf -maxdepth 1 -type f -name 'proxy.conf.bak*' 2>/dev/null | while read -r old; do
    if grep -qE "$legacy_lua_re" "$old" 2>/dev/null; then
      chattr -i -a "$old" >/dev/null 2>&1 || true
      rm -f "$old"
    fi
  done
}

test_and_reload() {
  "$NGINX_BIN" -t || return 1
  "$NGINX_BIN" -s reload || return 1
  sleep 2
  "$NGINX_BIN" -t || return 1
}

case "$ACTION" in
  install|update|repair)
    if [ ! -x "$NGINX_BIN" ] || [ ! -f "$NGINX_CONF" ]; then
      echo "Nginx/OpenResty is not installed"
      exit 1
    fi
    install_lua_json
    neutralize_legacy_darkjump_waf
    cp "$NGINX_CONF" "$NGINX_CONF.local_waf.bak"
    write_files
    migrate_config
    insert_include
    if ! test_and_reload; then
      cp "$NGINX_CONF.local_waf.bak" "$NGINX_CONF"
      "$NGINX_BIN" -t || true
      echo "local_waf install failed and nginx.conf was rolled back"
      exit 1
    fi
    echo "local_waf installed"
    ;;
  uninstall)
    [ -f "$NGINX_CONF" ] && remove_include
    rm -rf "$WAF_DIR" "$PLUGIN_DIR"
    [ -x "$NGINX_BIN" ] && test_and_reload || true
    echo "local_waf uninstalled"
    ;;
  *)
    echo "Usage: $0 install|uninstall|repair|update"
    exit 2
    ;;
esac
