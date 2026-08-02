#!/bin/sh
# WSO2's own hardening guidance: rotate the default admin password before any
# real use. [super_admin] in deployment.toml is what WSO2 IS reads to create
# the initial super-admin account on first boot.
set -e
TOML="${WSO2_SERVER_HOME}/repository/conf/deployment.toml"
sed -i 's/^password = "admin"$/password = "ChangeMe!2026-Hardened"/' "$TOML"
echo "  [stage2] rotated default super_admin password"
