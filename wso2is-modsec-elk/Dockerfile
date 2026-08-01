# =============================================================================
# WSO2 Identity Server 7.3 + OWASP ModSecurity CRS (nginx) — single image
# -----------------------------------------------------------------------------
# Base:   owasp/modsecurity-crs:nginx   (Debian 13, nginx 1.30 + ModSecurity3 + CRS)
# Copied: JDK 21 + WSO2 IS 7.3.0 distribution, taken directly from the official
#         wso2/wso2is:7.3.0 image (no re-download, no apt/network dependency
#         for the JDK — avoids drift from the vendor-published binaries).
#
# Both processes run in ONE container, supervised by `supervisord`:
#   - nginx + ModSecurity (CRS) listens on 8080/8443 and reverse-proxies to
#     WSO2 IS on 127.0.0.1:9443 (HTTPS, self-signed backend cert).
#   - WSO2 IS 7.3 runs as its own least-privilege user (wso2carbon, uid 802),
#     exactly as the vendor image does.
#
# Verified facts baked into this file (checked against the real images before
# writing, not assumed):
#   - wso2/wso2is:7.3.0  -> JAVA_HOME=/opt/java/openjdk, uid/gid 802,
#     WSO2_SERVER_HOME=/home/wso2carbon/wso2is-7.3.0, mgmt port 9443.
#   - owasp/modsecurity-crs:nginx -> BACKEND supports https://, PROXY_SSL=on
#     includes includes/proxy_backend_ssl.conf, PROXY_SSL_VERIFY defaults to
#     "off" already (fine for a self-signed backend cert).
# =============================================================================

FROM wso2/wso2is:7.3.0 AS wso2is-src

FROM owasp/modsecurity-crs:nginx
USER root

# supervisord to run nginx + wso2server.sh together; curl for health checks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends supervisor curl gosu \
    && rm -rf /var/lib/apt/lists/*

# --- Bring in WSO2 IS 7.3 + its bundled JDK from the official image ---------
COPY --from=wso2is-src /opt/java /opt/java
COPY --from=wso2is-src /home/wso2carbon /home/wso2carbon

# Recreate the same wso2carbon user/group (uid/gid 802) the vendor image uses,
# so ownership of the copied files is meaningful and WSO2 IS isn't run as root.
RUN groupadd -g 802 wso2 \
    && useradd -u 802 -g 802 -d /home/wso2carbon -s /bin/sh wso2carbon \
    && chown -R wso2carbon:wso2 /home/wso2carbon

ENV JAVA_HOME=/opt/java/openjdk \
    PATH="/opt/java/openjdk/bin:${PATH}" \
    WORKING_DIRECTORY=/home/wso2carbon \
    WSO2_SERVER_HOME=/home/wso2carbon/wso2is-7.3.0 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8

# --- Patch deployment.toml: tell WSO2 IS it's served through a reverse proxy
# on port 8443, so it generates correct external URLs (redirect_uri, SAML ACS,
# etc.) instead of advertising its own internal 9443.  Appended, not replaced,
# so we never fight the vendor's real defaults (verified no such section
# exists by default before adding it).
RUN printf '\n[transport.https.properties]\nproxyPort = "8443"\n' \
    >> "${WSO2_SERVER_HOME}/repository/conf/deployment.toml"

# --- Switch the "OverallAuthentication" event publisher from `logger`
# (writes to carbon log only) to `http`, POSTing each login/auth event as JSON
# to Logstash's http input in real time. This file and adapter type were
# confirmed to exist as shipped in IS 7.3 before this change was written.
RUN sed -i \
    -e 's#<to eventAdapterType="logger">#<to eventAdapterType="http">#' \
    -e '/<to eventAdapterType="http">/a\    <property name="publishingMode">non-blocking</property>\n    <property name="publishTimeout">0</property>\n    <property name="http.url">http://logstash:8084</property>' \
    "${WSO2_SERVER_HOME}/repository/deployment/server/eventpublishers/IsAnalytics-Publisher-wso2event-AuthenticationData.xml"

# --- nginx/ModSecurity: reverse proxy to WSO2 IS's HTTPS management port on
# localhost. PROXY_SSL_VERIFY is already "off" by default in this base image
# (fine here: the backend is our own WSO2 IS with a self-signed cert).
#
# NOTE: deliberately NOT setting PROXY_SSL=on. This image's own
# proxy_backend_ssl.conf.template references ${PROXY_SSL_CERT} /
# ${PROXY_SSL_CERT_KEY}, but the env vars it actually ships are
# PROXY_SSL_CERT_FILE / PROXY_SSL_CERT_KEY_FILE (name mismatch, verified by
# rendering the template standalone) -- enabling PROXY_SSL crashes nginx with
# "unknown proxy_ssl_cert variable". PROXY_SSL only controls presenting a
# CLIENT certificate for mutual TLS to the upstream, which WSO2 IS doesn't
# require, so leaving it at its default ("off") is correct here: nginx still
# completes a normal one-way TLS handshake with the self-signed backend via
# plain `proxy_pass https://...`, it just doesn't verify that backend's cert
# (proxy_ssl_verify is independently "off" by default already).
ENV BACKEND=https://127.0.0.1:9443 \
    PORT=8080 \
    SSL_PORT=8443 \
    MODSEC_RULE_ENGINE=On \
    PARANOIA=1 \
    ANOMALY_INBOUND=5 \
    MODSEC_AUDIT_ENGINE=RelevantOnly \
    MODSEC_AUDIT_LOG_FORMAT=JSON \
    MODSEC_AUDIT_LOG=/var/log/modsecurity/audit/modsec_audit.log

RUN mkdir -p /var/log/modsecurity/audit && chmod 777 /var/log/modsecurity/audit

COPY docker/supervisord.conf /etc/supervisor/conf.d/wso2is-modsec.conf
COPY docker/start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 8080 8443 9443

ENTRYPOINT ["/start.sh"]
