#!/bin/sh
# -----------------------------------------------------------------------------
# Single entrypoint for the combined WSO2 IS 7.3 + ModSecurity/nginx image.
#
# Step 1 reuses the *vendor's own* /docker-entrypoint.sh to render the nginx +
# ModSecurity config templates (envsubst on BACKEND/PROXY_SSL/PORT/etc,
# self-signed cert generation, CRS rule activation) exactly as the official
# owasp/modsecurity-crs:nginx image would on a normal `docker run`. We pass it
# a harmless final command ("nginx -v") so it renders everything as a side
# effect, prints the nginx version, and returns -- instead of using `exec`
# ourselves, which would replace this whole script's process and never let us
# reach step 2.
#
# Step 2 replicates the official wso2/wso2is:7.3.0 image's own
# docker-entrypoint.sh behaviour: if a config/artifact overlay was mounted,
# copy it over the WSO2 IS distribution before first start.
#
# Step 3 hands off to supervisord, which runs nginx and wso2server.sh as
# separate, supervised, auto-restarting processes in this one container.
# -----------------------------------------------------------------------------
set -e

echo "[start.sh] Rendering nginx + ModSecurity config from templates..."
sh /docker-entrypoint.sh nginx -v

echo "[start.sh] Applying WSO2 IS config/artifact overlays (if any)..."
config_volume="${WORKING_DIRECTORY}/wso2-config-volume"
artifact_volume="${WORKING_DIRECTORY}/wso2-artifact-volume"

if [ -d "$config_volume" ] && [ "$(ls -A "$config_volume" 2>/dev/null)" ]; then
    cp -RL "$config_volume"/* "$WSO2_SERVER_HOME"/
    chown -R wso2carbon:wso2 "$WSO2_SERVER_HOME"
fi
if [ -d "$artifact_volume" ] && [ "$(ls -A "$artifact_volume" 2>/dev/null)" ]; then
    cp -RL "$artifact_volume"/* "$WSO2_SERVER_HOME"/
    chown -R wso2carbon:wso2 "$WSO2_SERVER_HOME"
fi

echo "[start.sh] Handing off to supervisord (nginx + wso2server.sh)..."
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
