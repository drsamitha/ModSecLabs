#!/bin/sh
# HSTS at the edge (nginx/WAF), applied uniformly to every path.
#
# WSO2 IS itself only has a per-webapp HSTS filter on the legacy /carbon
# context (web.xml's HttpHeaderSecurityFilter, off by default) -- the newer
# React /console app has no such filter at all (verified: its web.xml has zero
# <filter> definitions). Patching each webapp individually is a losing,
# incomplete game. Real deployments enforce HSTS once, at the reverse-proxy
# edge, covering every path uniformly -- so that's what this does.
#
# Insert after the 2nd occurrence of the proxy include (the HTTPS server
# block; the 1st is the HTTP block, where HSTS is meaningless).
set -e
CONF=/etc/nginx/conf.d/default.conf
awk '
/include includes\/proxy_backend.conf;/{
    c++
    print
    if (c==2) print "        add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
    next
}
{ print }
' "$CONF" > /tmp/default.conf.new && mv /tmp/default.conf.new "$CONF"
echo "  [stage2] added HSTS header at the nginx/WAF edge (all paths, HTTPS only)"
