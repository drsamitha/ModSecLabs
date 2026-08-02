#!/bin/sh
# Directly sed-patching catalina-server.xml does NOT stick: WSO2 IS
# regenerates that file from a Jinja2 template
# (repository/resources/conf/templates/.../catalina-server.xml.j2) on every
# single boot, driven by deployment.toml -- so a raw XML edit is silently
# overwritten before Tomcat ever reads it. Verified by inspecting the .j2
# template: the Connector's attributes (including "server") are populated
# from the [transport.http.properties] / [transport.https.properties] maps in
# deployment.toml. Adding the key there is the only edit that survives a
# reboot.
set -e
TOML="${WSO2_SERVER_HOME}/repository/conf/deployment.toml"
sed -i '/\[transport.https.properties\]/a server = "webserver"' "$TOML"
printf '\n[transport.http.properties]\nserver = "webserver"\n' >> "$TOML"
echo "  [stage2] overrode Tomcat's Server header via deployment.toml (survives reboot)"
