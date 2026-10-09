ARG KEYCLOAK_BASE_IMAGE=quay.io/keycloak/keycloak:26.8.0@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc

FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS extension-builder
WORKDIR /src
COPY extensions/moneybee-email-otp/ ./
RUN mvn --batch-mode --no-transfer-progress verify

FROM ${KEYCLOAK_BASE_IMAGE} AS builder
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true
COPY --from=extension-builder /src/target/moneybee-email-otp-1.0.0.jar /opt/keycloak/providers/moneybee-email-otp.jar
COPY themes /opt/keycloak/themes
RUN /opt/keycloak/bin/kc.sh build

FROM ${KEYCLOAK_BASE_IMAGE}
USER 0
COPY --from=builder /opt/keycloak/ /opt/keycloak/
# Reduce attack surface: this deployment uses PostgreSQL, never SQL Server.
RUN rm -f /opt/keycloak/lib/lib/main/com.microsoft.sqlserver.mssql-jdbc-*.jar \
    && test -z "$(find /opt/keycloak -type f -name 'com.microsoft.sqlserver.mssql-jdbc-*.jar' -print -quit)"
USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
