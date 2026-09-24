# Phase 10: Enterprise Security Operations, Threat Investigations & Security Campaigns

## 1. Security Operations Architecture
Phase 10 transforms Trust & Verify into a robust platform for enterprise security operations by integrating Threat Intelligence, Incident Management, IOC Tracking, and Security Campaigns securely within Organization boundaries. 

The architecture does not replace existing local-first scanning or the Phase 2 Risk Engine but builds an organizational orchestration layer above them.

## 2. IOC Management
An Indicator of Compromise (IOC) system manages malicious IPs, Domains, URLs, Hashes, and Emails.
- **Normalization:** IOCs are normalized (e.g., lowercased, trimmed) before storage.
- **Fingerprinting:** A deterministic SHA-256 fingerprint of `type + normalized_value` enforces uniqueness per organization.
- **Enrichment:** IOCs can be enriched via the existing Phase 4 Threat Intelligence providers (VirusTotal, URLhaus, etc.) without exposing direct API access or SSRF vectors.

## 3. Incident Management
Incidents map security events to a workflow.
- **Lifecycle:** Tracks from `NEW` through `INVESTIGATING` to `CLOSED`.
- **Deduplication:** Analysts can relate incidents to specific IOCs and tag them by categories like `PHISHING` or `ACCOUNT_COMPROMISE`.
- **Audit Logging:** An append-only `incident_events` table captures all state transitions (status, severity, assignment).

## 4. Investigations
A lightweight workspace groups IOCs and notes for active threat analysis.
- Connects IOCs, findings, and metadata.
- Preserves analysis notes securely behind organization authentication boundaries.

## 5. Security Campaigns
Campaigns facilitate organizational security awareness through simulation.
- **Simulated & Educational:** Designed explicitly for training. Campaigns do not collect passwords, real credentials, or deploy malware.
- **Safety Measures:** Strict launch confirmations are required.
- **RBAC:** Only highly privileged roles (Admin, Owner, or explicitly designated Managers) can create or launch campaigns.

## 6. RBAC Integration
Phase 10 extends the Phase 9 RBAC system seamlessly:
- **`security.read` / `security.manage`**
- **`incidents.read` / `incidents.create` / `incidents.update`**
- **`iocs.read` / `iocs.create` / `iocs.enrich`**
- **`campaigns.launch` / `campaigns.cancel`**

## 7. Organization Isolation
Every operation enforce the `req.organizationId` context, ensuring that security records never leak between tenant boundaries. Cross-tenant access is physically blocked at the SQL query level by bounding all `SELECT`, `UPDATE`, and `DELETE` commands to the verified organization ID.

## 8. Threat Intelligence Integration
Enrichment relies entirely on the established Threat Intelligence API gateway, guaranteeing:
- Secure, hidden API keys.
- SSRF protections on IP and Domain resolution.
- Timeout controls.
- Cache reuse.

## 9. Privacy & Audit Logging
No raw passwords or API keys are logged. The `organization_events` and `incident_events` tables trace every analyst action (creating IOCs, enriching IOCs, closing investigations) for transparency and forensic auditing.

## 10. Known Limitations
- Enrichment types are mapped to existing Provider capabilities (URL, Domain, Hash). IP enrichment is partially mapped based on provider support.
- File attachment parsing remains scoped to local engines rather than automated external distribution for privacy.
- Custom automated rules (SOAR) are out of scope.
