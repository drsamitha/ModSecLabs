#!/bin/sh
# -----------------------------------------------------------------------------
# Single entrypoint for the combined WSO2 IS 7.3 + ModSecurity/nginx image.
#
# Step 1 reuses the vendor's own /docker-entrypoint.sh to render nginx +
# ModSecurity config templates (self-signed cert, envsubst on BACKEND/PORT/
# etc, CRS rule activation) exactly as owasp/modsecurity-crs:nginx would on a
# normal `docker run`. We pass a harmless final command ("nginx -v") so it
# renders everything as a side effect and returns, instead of `exec`ing
# ourselves (which would replace this whole script and never reach step 2).
#
# Step 2 runs every script in /hardening.d/*.sh, in filename order. This is
# how each lab stage progressively hardens WSO2 IS: mount a different
# /hardening.d directory per stage and the SAME image applies exactly the
# fixes for that stage, against the real config files
# (deployment.toml, web.xml, catalina-server.xml) -- read the mounted scripts
# to see precisely what each stage changes and why.
#
# Step 3 replicates the official wso2/wso2is:7.3.0 entrypoint's config/
# artifact-volume overlay behaviour, then hands off to supervisord.
# -----------------------------------------------------------------------------
set -e

echo "[start.sh] Rendering nginx + ModSecurity config from templates..."
sh /docker-entrypoint.sh nginx -v

echo "[start.sh] Applying hardening.d scripts (if any)..."
if [ -d /hardening.d ]; then
    for f in /hardening.d/*.sh; do
        [ -e "$f" ] || continue
        echo "[start.sh]   -> $f"
        sh "$f"
    done
fi

echo "[start.sh] Applying WSO2 IS config/artifact overlays (if any)..."
config_volume="${WORKING_DIRECTORY}/wso2-config-volume"
artifact_volume="${WORKING_DIRECTORY}/wso2-artifact-volume"

if [ -d "$config_volume" ] && [ "$(ls -A "$config_volume" 2>/dev/null)" ]; then
    cp -RL "$config_volume"/* "$WSO2_SERVER_HOME"/
fi
if [ -d "$artifact_volume" ] && [ "$(ls -A "$artifact_volume" 2>/dev/null)" ]; then
    cp -RL "$artifact_volume"/* "$WSO2_SERVER_HOME"/
fi
chown -R wso2carbon:wso2 "$WSO2_SERVER_HOME"

# nginx's very first launch was observed, intermittently, to fail with a
# ModSecurity rules-file parse error that is NOT reproducible against the
# exact same file content on a retry -- almost certainly a filesystem-timing
# race on the (potentially volume-mounted) rules directory settling right
# after container start. `nginx -t` exercises the identical config-parsing
# path without binding a port, so looping it here until it passes means
# supervisord only ever launches nginx once that race has already resolved.
echo "[start.sh] Validating nginx/ModSecurity config before starting nginx..."
i=0
until nginx -t >/tmp/nginx-t.out 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 15 ]; then
        echo "[start.sh] nginx config still invalid after $i attempts, giving up:"
        cat /tmp/nginx-t.out
        exit 1
    fi
    sleep 1
done
echo "[start.sh] nginx config OK after $i retries."

echo "[start.sh] Redirecting nginx access/error logs to real files (not stdout/stderr)..."
rm -f /var/log/nginx/access.log /var/log/nginx/error.log
touch /var/log/nginx/access.log /var/log/nginx/error.log

echo "[start.sh] Handing off to supervisord (nginx + wso2server.sh)..."
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
