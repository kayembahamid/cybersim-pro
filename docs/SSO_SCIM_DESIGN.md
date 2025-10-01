# CyberSim Pro Identity & Provisioning Design

This document outlines the architecture and phased implementation plan for delivering enterprise-grade SSO and SCIM provisioning so Access Management control **AM-01** can transition from "in-progress" to "operational".

---

## 1. Goals

- **SSO**: Enable SAML 2.0 and OIDC sign-in with Okta / Azure AD / Entra ID.
- **MFA Enforcement**: Honour IdP policies and expose per-role MFA requirements.
- **Just-In-Time (JIT) Access**: Map IdP group claims to CyberSim roles with optional approval gating for privileged actions.
- **SCIM Provisioning**: Support automated user and group lifecycle (create, update, deactivate) with soft-delete grace periods.
- **Auditability**: Record provisioning changes and login events in the existing chained audit log.

---

## 2. Architecture Overview

```
+-------------+         SAML/OIDC          +----------------+
|  Identity   |  ───────────────────────▶  |  Auth Gateway  |
|  Provider   |                            | (new service)  |
+-------------+                            +--------+-------+
                                              │Tokens /
                                              │Sessions
                                              ▼
                                      +---------------+
                                      | MCP Server    |
                                      | (current app) |
                                      +-------+-------+
                                              │SCIM Webhooks
                                              ▼
                                      +---------------+
                                      | Provisioner   |
                                      | (new module)  |
                                      +---------------+
```

### Components

- **Auth Gateway** (`src/identity/authGateway.ts`): Handles SAML/OIDC flow, signature validation, role mapping, MFA policy checks, and emits identity audit events.
- **Provisioner Service** (`src/identity/scimProvisioner.ts`): Exposes SCIM 2.0 `/Users` and `/Groups` endpoints, persists roster.
- **Role Mapper** (`src/identity/roleMapper.ts`): Configurable mapping of IdP groups → CyberSim roles/approvals.
- **Audit Sink**: Extends `AuditLogger` to capture identity events.

---

## 3. Data Model Changes

- Extend `server.json` with `identity` block:
  ```json
  {
    "identity": {
      "sso": {
        "enabled": true,
        "protocol": "oidc",
        "issuer": "https://example.okta.com",
        "audience": "cybersim-pro",
        "acsUrl": "https://cybersim.example.com/api/sso/assert",
        "sessionTtlMinutes": 60,
        "mfaEnforcedRoles": ["controller", "admin"],
        "oidc": {
          "issuer": "https://example.okta.com",
          "audience": "cybersim-pro",
          "publicKeys": [{ "kid": "primary", "pem": "-----BEGIN CERTIFICATE-----..." }],
          "mfaSatisfiedAmrValues": ["mfa", "otp", "hwk"],
          "mfaSatisfiedAcrValues": ["urn:okta:assurance:level2"]
        },
        "saml": {
          "entityId": "https://cybersim.example.com/sp",
          "acsUrl": "https://cybersim.example.com/api/sso/assert",
          "audience": "https://cybersim.example.com/sp",
          "certificateFingerprints": ["A1:B2:C3:D4"]
        }
      },
      "scim": {
        "enabled": true,
        "bearerToken": "env:CYBERSIM_SCIM_TOKEN",
        "baseUrl": "https://cybersim.example.com/api/scim"
      },
      "roleMappings": "./config/role-mappings.json"
    }
  }
  ```
- New tables/collections (`identity_users`, `identity_groups`) or reuse existing config store.
- Domain artefacts (scenarios, simulations, investigations, reports, forensic outputs, metrics, and control feed entries) now persist a sanitized `provenance` envelope capturing the resolved actor, roles, protocol, and MFA posture so downstream analytics can prove IdP lineage without exposing raw session tokens.
- Provide a post-upgrade task (`npm run migrate:provenance`) to retrofit historical JSONL evidence before regulators request longitudinal exports.

---

## 4. API Surface

### SSO Endpoints
- `GET /api/sso/metadata` – returns SAML metadata.
- `POST /api/sso/assert` – consumes SAML assertions, issues session tokens.
- `POST /api/auth/oidc/callback` – optional OIDC callback.

### SCIM Endpoints
- `GET /api/scim/v2/Users`
- `POST /api/scim/v2/Users`
- `PATCH /api/scim/v2/Users/{id}`
- `DELETE /api/scim/v2/Users/{id}` (soft-delete)
- Equivalent group endpoints.

All SCIM endpoints require bearer token `CYBERSIM_SCIM_TOKEN`, rotateable via secrets manager.

---

## 5. Security Considerations

- Sign SAML assertions by validating XML signatures, fingerprinting the IdP certificate, and enforcing `Conditions`/`SubjectConfirmationData` windows.
- Enforce TLS mutual auth when feasible; minimum requirement TLS 1.2.
- Rate-limit SCIM updates to protect from IdP loops.
- Log all provisioning changes including actor (`system`, `scim`, `manual`).
- Support break-glass local admin with short-lived emergency credentials.

---

## 6. Rollout Plan

1. **Phase 0 – Foundations**
   - [ ] Implement configuration parsing (`src/config/identityConfig.ts`).
   - [ ] Ship role mapping stub (`config/role-mappings.example.json`).
   - [ ] Extend audit logger with `identity` event type.

2. **Phase 1 – OIDC/SAML Auth Gateway**
   - [ ] Build minimal OIDC integration (PKCE, auth code flow) behind feature flag.
   - [ ] Implement SAML metadata + assertion consumption.
   - [ ] Add CLI onboarding helper to print ACS URLs and metadata.

3. **Phase 2 – SCIM Provisioning**
   - [ ] Expose SCIM `/Users` endpoints with in-memory store.
   - [ ] Persist to durable store (TBD: Postgres or JSON files) with soft-delete.
   - [ ] Map groups to role policies (reusing RBAC config).

4. **Phase 3 – Approvals & JIT Access**
   - [ ] Integrate with existing approval token workflow; allow auto-approval for low-risk roles.
   - [ ] Surface access change logs in compliance report.

5. **Phase 4 – Hardening**
   - [ ] Pen-test identity layer.
   - [ ] Document operational runbooks and recovery procedures.
   - [ ] Update `controlCatalog` statuses to "operational" when completed.

---

## 7. Open Questions

- Preferred persistence layer for identity roster? (Option: reuse metrics SQLite vs. dedicated DB).
- Should role mapping support regex/group attributes or static list only?
- How to expose user-visible session management (logout everywhere) in MCP context?
- Need to confirm customer expectations for SCIM patch semantics (Okta vs Azure nuances).

---

_Last updated: 2024-12-02_
