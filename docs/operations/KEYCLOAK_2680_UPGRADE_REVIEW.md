# Keycloak 26.8.0 security upgrade candidate (SOURCE ONLY)

## Immutable provenance
- Base: `quay.io/keycloak/keycloak:26.8.0@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc`
- Registry manifest digest was read from Quay; official 26.8.0 base contains Netty 4.1.138.Final.
- Obsolete manual Netty 4.1.137 replacement is removed; do not rename jars to older coordinates.
- MoneyBee email OTP provider and repository themes are built into the custom candidate.
- SQL Server JDBC driver is excluded from the PostgreSQL-only runtime.
- Build and security scan the exact candidate image digest in protected CI. No local or production release is implied.

## Required release gates (all must pass)
1. Fresh independent security review and exact source/merge-result CI on the unchanged PR head.
2. Build the custom image; verify the MoneyBee extension loads and custom themes are present.
3. Scan the exact image digest and resolve critical/high findings without suppressing gates.
4. Take encrypted off-host PostgreSQL backup; prove checksum and restore in an isolated database.
5. Test issuer/JWKS, PKCE login, OTP, account recovery, expired/revoked/invalid tokens, scopes, tenant isolation, and Kong/Middleware rejection paths in staging.
6. Verify `auth.codestra.co` hostname/proxy/header and certificate behavior from a browser.
7. Rehearse rollback using the exact prior approved image and verified database restore procedure; record evidence and recovery point.
8. Promote only by protected main -> staging -> production release flow after authorization; keep `PRODUCTION_GO=NO` and external effects OFF until certified.

**Not done by this source PR:** no production deployment, no realm/client writes, no database migration, no provider activation. Running production may remain at 26.7.2 until a separately approved cutover.
