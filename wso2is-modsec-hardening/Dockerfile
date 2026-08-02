# =============================================================================
# WSO2 Identity Server 7.3 + OWASP ModSecurity CRS (nginx) — hardening series
# -----------------------------------------------------------------------------
# Same verified base mechanics as the ModSecLabs WSO2/ELK project (base image,
# JDK+distribution copy, supervisord, proxyPort patch, PROXY_SSL left off due
# to a confirmed name-mismatch bug in this CRS-nginx image version).
#
# NEW for this series: a `/hardening.d/*.sh` hook mechanism. Each lab stage
# mounts a different directory of small, idempotent shell scripts that patch
# WSO2 IS's real config files (deployment.toml, web.xml, catalina-server.xml)
# BEFORE the server starts. This lets ONE image serve every stage of the
# hardening curriculum -- the learner sees exactly what changed by reading the
# mounted scripts, not by comparing two different pre-baked images.
# =============================================================================

FROM wso2/wso2is:7.3.0 AS wso2is-src

FROM owasp/modsecurity-crs:nginx
USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends supervisor curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=wso2is-src /opt/java /opt/java
COPY --from=wso2is-src /home/wso2carbon /home/wso2carbon

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

# Reverse-proxy needs to know it's fronted on 8443 so WSO2 IS generates
# correct external URLs (redirect_uri, SAML ACS, etc). This is a deployment
# mechanic, not a hardening step, so it's baked into every stage.
RUN printf '\n[transport.https.properties]\nproxyPort = "8443"\n' \
    >> "${WSO2_SERVER_HOME}/repository/conf/deployment.toml"

ENV BACKEND=https://127.0.0.1:9443 \
    PORT=8080 \
    SSL_PORT=8443 \
    MODSEC_RULE_ENGINE=On \
    PARANOIA=1 \
    ANOMALY_INBOUND=5 \
    MODSEC_AUDIT_ENGINE=RelevantOnly \
    MODSEC_AUDIT_LOG_FORMAT=JSON \
    MODSEC_AUDIT_LOG=/var/log/modsecurity/audit/modsec_audit.log

RUN mkdir -p /var/log/modsecurity/audit /hardening.d && chmod 777 /var/log/modsecurity/audit

COPY docker/supervisord.conf /etc/supervisor/conf.d/wso2is-modsec.conf
COPY docker/start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 8080 8443 9443

ENTRYPOINT ["/start.sh"]
