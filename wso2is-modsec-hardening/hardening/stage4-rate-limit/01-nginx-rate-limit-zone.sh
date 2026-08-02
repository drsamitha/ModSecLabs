#!/bin/sh
# Rate-limit the auth endpoints at the edge -- NOT via ModSecurity.
#
# Verified limitation: this image's ModSecurity engine is libmodsecurity3,
# which silently no-ops `initcol`/persistent collections (the classic
# ModSecurity v2 rate-limiting recipe using per-IP counters). A test rule
# using initcol+setvar+expirevar loaded without error but never actually
# blocked anything after the threshold -- confirming the engine accepts the
# syntax but doesn't implement stateful storage. This also matches how real
# organizations do it (per the hardening research): rate limiting is a
# reverse-proxy/API-gateway concern, not a WAF pattern-matching concern.
#
# Technique: nginx's native `limit_req`, scoped to ONLY /oauth2/token and
# /commonauth via a `map` that produces an empty key (nginx's documented way
# to exempt a request from limiting) for every other path -- so the rest of
# the site is completely unaffected by hammering the auth endpoints.
set -e
NGINX_CONF=/etc/nginx/nginx.conf
sed -i '/^http {/a\
    map $uri $rl_key { default ""; "~*^/oauth2/token" $binary_remote_addr; "~*^/commonauth" $binary_remote_addr; }\
    limit_req_zone $rl_key zone=authlimit:10m rate=5r/m;\
    limit_req_status 429;' "$NGINX_CONF"
echo "  [stage4] added limit_req_zone 'authlimit' (5r/m, keyed only for /oauth2/token and /commonauth)"
