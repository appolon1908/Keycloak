from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
POM = ROOT / "extensions" / "moneybee-email-otp" / "pom.xml"
BASE = ("quay.io/keycloak/keycloak:26.8.0@sha256:"
        "b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc")


class KeycloakNettySecurityTests(unittest.TestCase):
    def test_immutable_security_patched_upstream_base(self) -> None:
        self.assertIn(f"ARG KEYCLOAK_BASE_IMAGE={BASE}", DOCKERFILE)
        self.assertEqual(DOCKERFILE.count("FROM ${KEYCLOAK_BASE_IMAGE}"), 2)
        self.assertNotIn("netty-security-fix", DOCKERFILE)
        self.assertNotIn("io.netty.netty-handler-4.1.136.Final.jar", DOCKERFILE)
        self.assertNotIn("io.netty.netty-codec-http-4.1.136.Final.jar", DOCKERFILE)
        self.assertNotIn("4.1.137.Final.jar", DOCKERFILE)

    def test_custom_provider_and_themes_are_preserved(self) -> None:
        self.assertIn("RUN mvn --batch-mode --no-transfer-progress verify", DOCKERFILE)
        self.assertIn("/opt/keycloak/providers/moneybee-email-otp.jar", DOCKERFILE)
        self.assertIn("COPY themes /opt/keycloak/themes", DOCKERFILE)
        self.assertIn("RUN /opt/keycloak/bin/kc.sh build", DOCKERFILE)
        self.assertIn("USER 1000", DOCKERFILE)

    def test_extension_maven_spi_version_matches_runtime(self) -> None:
        root = ET.parse(POM).getroot()
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        self.assertEqual(root.findtext("./m:properties/m:keycloak.version", namespaces=ns), "26.8.0")

    def test_sql_server_driver_excluded_from_postgres_image(self) -> None:
        self.assertIn(
            "rm -f /opt/keycloak/lib/lib/main/com.microsoft.sqlserver.mssql-jdbc-*.jar",
            DOCKERFILE,
        )
        self.assertIn("-name 'com.microsoft.sqlserver.mssql-jdbc-*.jar'", DOCKERFILE)
