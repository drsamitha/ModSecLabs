#!/bin/sh
# Apply the zone defined in 01-nginx-rate-limit-zone.sh inside the (single,
# shared) proxy location block. burst=3 nodelay: allow a small burst (e.g. a
# legitimate retry after a network blip) before throttling kicks in.
set -e
CONF=/etc/nginx/conf.d/default.conf
awk '
/include includes\/proxy_backend.conf;/{
    print
    print "        limit_req zone=authlimit burst=3 nodelay;"
    next
}
{ print }
' "$CONF" > /tmp/default.conf.new && mv /tmp/default.conf.new "$CONF"
echo "  [stage4] applied limit_req (burst=3, nodelay) to the proxy location"
