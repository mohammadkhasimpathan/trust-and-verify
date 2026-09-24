# Phase 9: Organizations, Teams, Roles & Administration

## 1. Organization Architecture
Trust & Verify introduces a secure, multi-tenant organization architecture built on top of the existing Local-First + Optional Cloud Account model. 

Users retain complete ownership of their personal accounts and personal data (scans, training, history, certificates). Organizations represent distinct, isolated workspaces that users can optionally join or create. 

Data isolation is strictly enforced at the database level. Organization-specific actions, data, and metadata never bleed into a user's personal scope or into other organizations.

## 2. Membership Model
A user's relationship to an organization is defined by the `organization_members` table. A user can belong to multiple organizations but cannot join the same organization twice. 
The membership status explicitly tracks active vs. inactive members, allowing safe revocation without full deletion, preserving audit integrity.

## 3. RBAC Architecture
Access control is implemented via Role-Based Access Control (RBAC). 
Every organization member is assigned exactly one role per organization.
Roles are predefined system constants: `Owner`, `Admin`, `Manager`, `Member`, `Viewer`.
Permissions dictate the exact actions a role can perform. 

## 4. Permission Model
Permissions are granular, dot-notated strings (e.g., `organization.update`, `members.invite`).
The server-side authorization engine validates:
1. Authentication state (Valid Session)
2. Organization Membership (Valid & Active)
3. Role Permission (Role explicitly mapped to the required permission)

## 5. Teams
Organizations can contain multiple teams. Teams are logical groupings of organization members.
Team membership requires organization membership. If a user leaves the organization, they are automatically removed from all teams via foreign key cascading constraints.

## 6. Invitations
New members are invited via email. Invitations are:
- Cryptographically secure (`crypto.randomBytes(32)`)
- Hashed at rest (SHA-256)
- Time-bound (expires in 7 days)
- Single-use

Accepting an invitation verifies the token and securely links the authenticated user to the organization.

## 7. Ownership
Every organization has an `owner_user_id`. The Owner holds all permissions and cannot be silently removed or demoted. 
Ownership transfers are protected by explicit, transactional endpoints ensuring the organization never enters a state without a valid owner.

## 8. Audit Logs
Security and administrative actions within an organization (e.g., Member Joined, Team Created, Role Changed) are logged to the `organization_events` table. 
These events are strictly scoped to the organization and sanitized to prevent exposing sensitive credentials or private PII.

## 9. Training Assignments Foundation
Phase 9 lays the groundwork for organization-wide training assignments. The isolated data model ensures that personal training progress does not conflict with organization-mandated training objectives.

## 10. Data Isolation
Personal data is completely separated from organization data.
Querying organization resources always requires an explicit `organization_id` bound to the authenticated user's session.

## 11. Sync Behavior
The SyncEngine will respect organization context. Local-first caching is strictly read-only for organization data when offline. Destructive or sensitive operations (deletion, role change) require real-time server authorization.

## 12. Security Model
- **IDOR Protection:** All queries scope resources strictly to the authenticated user's verified organization context.
- **Mass Assignment:** APIs extract only allowlisted fields.
- **Privilege Escalation:** Client-side role modifications are rejected.
- **Transactions:** Complex operations (e.g., Ownership Transfer, Org Creation) run inside SQLite transactions to prevent partial state corruption.

## 13. Known Limitations
- Email delivery relies on the mocked `console` email service.
- The UI layer for Organizations requires explicit wiring into `app.js` and `accountUi.js` using the provided APIs.
- Custom Roles are deferred to a future phase.
