# PROMPTS.md — AI Engineering Log & Error Interception Record

**Project:** TrustVault — Secure Document Sharing with Real Audit Trail  
**Candidate:** Snovasys Fresher Hiring Challenge 2026  
**Scope:** Chronological engineering audit detailing tool interactions, AI hallucinations/architectural flaws, critical catches in authorization & audit logic, and robust manual corrections.

---

### Entry 1: Authorization Check Placement Flaw (Client-Side Concealment Trap)
- **Date:** 2026-10-19
- **Prompt:**
  > "Build the React document details view and download handler for TrustVault. Ensure viewers cannot download files they don't have access to."
- **What it produced:**
  The AI generated a React component that checked `user.role === 'viewer'` and conditionally removed the `<button>Download</button>` from the DOM. On the download endpoint, it generated:
  ```typescript
  // AI-generated flawed snippet:
  app.get('/api/documents/:id/download', (req, res) => {
    const doc = db.find(d => d.id === req.params.id);
    return res.send(doc.content);
  });
  ```
- **What was wrong with it, specifically:**
  This was a catastrophic authorization vulnerability violating Non-Negotiable Standard One ("A document is reachable only by someone who was granted it. Not 'the button is hidden'. Not 'the page checks'."). Any user using `curl` or Postman could download David Vance's executive salary files simply by passing `doc-hr-101` in the URL, as the server executed zero authorization checks.
- **What we did instead:**
  We replaced this client-only check with strict server-side authorization enforcement. We built `evaluateAccess(user, doc, 'DOWNLOAD')` inside `src/services/securityEngine.ts`. Every download request checks the caller's active identity, verifies document ownership or explicit named grant status in `doc.grants`, returns `HTTP 403 Forbidden` if missing, and logs a `DENIED_403` security alert into the tamper-evident audit ledger.
  *Fix Reference:* Implemented in commit `feat(security): server-side-authorization-barrier`.

---

### Entry 2: Instant Revocation JWT Caching Anti-Pattern
- **Date:** 2026-10-20
- **Prompt:**
  > "Implement the document permission revocation flow so that an owner can revoke access from external contractors."
- **What it produced:**
  The AI designed a tokenized permission architecture: when access was granted, it issued a signed JWT token with a 15-minute expiration time (`expiresIn: '15m'`). On revocation, it removed the user from a database table and said:
  > *"When the owner revokes access, the database row is deleted. The client's JWT will naturally expire within 15 minutes, ensuring security without polling."*
- **What was wrong with it, specifically:**
  This completely violates Non-Negotiable Standard Three ("Taking access away works immediately. Whatever you have issued to that person before that moment stops working."). In a breach, termination, or accidental grant scenario, a 15-minute exposure window is catastrophic. The revoked user could continue downloading confidential patent files for 900 seconds.
- **What we did instead:**
  We implemented **zero-TTL, version-invalidated authorization**:
  1. Revocation immediately mutates the grant record to `status: 'REVOKED'`.
  2. The document's `permissionVersion` is incremented.
  3. The target user's session version is incremented.
  4. Every request checks live server state against the document version.
  The moment an owner clicks "Revoke", any request arriving even 1 millisecond later fails immediately with `HTTP 403`.
  *Fix Reference:* Implemented in commit `fix(authz): zero-ttl-instant-revocation`.

---

### Entry 3: Mutable Audit Trail Anti-Pattern (SQL Update Flaw)
- **Date:** 2026-10-21
- **Prompt:**
  > "Create an audit trail database schema and API to track uploads, downloads, and permission changes."
- **What it produced:**
  The AI created a standard CRUD table:
  ```sql
  CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    user_id INT,
    action VARCHAR,
    details TEXT
  );
  ```
  Along with endpoints:
  ```typescript
  app.put('/api/audit-logs/:id', (req, res) => {
    // AI added: update log description in case administrator made a typo
  });
  ```
- **What was wrong with it, specifically:**
  An audit trail that can be updated is legally and cryptographically worthless. A rogue administrator or attacker could exfiltrate documents and quietly update or delete the log rows to remove traces (violating Standard Two: "An audit trail that can be quietly altered is not evidence, and we will ask you what stops that.").
- **What we did instead:**
  We built a **cryptographic SHA-256 Merkle-style hash chain** (`src/services/cryptoLedger.ts`). Each entry incorporates the cryptographic hash of the preceding entry:
  $$\text{Hash}_n = \text{SHA-256}(n \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{status} \parallel \text{Hash}_{n-1})$$
  No updates or deletions are permitted. We implemented `verifyAuditChainIntegrity()`, which re-computes every block signature from Genesis to Head. Any modification to a past row breaks subsequent links and is immediately exposed.
  *Fix Reference:* Implemented in commit `feat(audit): sha256-hash-chain-ledger`.

---

### Entry 4: Superficial File Validation (Extension-Only Whitelisting)
- **Date:** 2026-10-22
- **Prompt:**
  > "Add validation for document uploads to ensure only legitimate enterprise documents can be stored."
- **What it produced:**
  The AI provided a simple regex check:
  ```typescript
  const isValid = /\.(pdf|docx|txt)$/i.test(file.name);
  if (!isValid) return res.status(400).send('Invalid file extension');
  ```
- **What was wrong with it, specifically:**
  Checking only the file extension is trivially bypassed. An attacker can take an executable binary (`backdoor.exe`), rename it to `backdoor.pdf`, and bypass the check. The file would be saved and served to internal clients.
- **What we did instead:**
  We implemented **multi-layer file validation** in `validateAndUploadDocument()`:
  1. Magic byte sniffing: Inspects byte signatures to detect and reject Windows PE executables (`MZ` header) and Linux binaries (`\x7fELF`).
  2. MIME type cross-validation against known extension pairings.
  3. Path traversal sanitization: Rejection of directory climbing patterns (`../`, `..\`, `%2e%2e`, null bytes).
  4. Hard payload size boundary ceiling (15MB).
  *Fix Reference:* Implemented in commit `feat(validation): magic-byte-sniffing-and-traversal-defense`.

---

### Entry 5: Autonomous AI Permission Escalation Trap
- **Date:** 2026-10-23
- **Prompt:**
  > "Add an AI assistant that analyzes documents and manages permissions."
- **What it produced:**
  The AI suggested an autonomous background function:
  ```typescript
  async function autoAssignPermissions(doc) {
    const aiRecommendation = await gemini.analyze(doc.content);
    for (const user of aiRecommendation.suggestedUsers) {
      db.grants.add({ docId: doc.id, userId: user.id }); // Automatically granted!
    }
  }
  ```
- **What was wrong with it, specifically:**
  This explicitly violated the challenge requirement: *"The machine must never widen access on its own. A person confirms, and both the suggestion and the decision go into the audit."* Allowing an LLM to directly alter production access control tables introduces prompt injection vulnerabilities and unpredictable privilege creep.
- **What we did instead:**
  We built `generateAIPermissionSuggestions()` inside `src/services/aiAdvisor.ts`. The AI generates read-only recommendations with confidence scores and reasoning. The machine has **zero** permission to write to the database. A human document owner must explicitly review each suggestion and confirm with a manual grant. Furthermore, both the generation of the recommendation and the owner's confirmation are logged to the cryptographic audit trail.
  *Fix Reference:* Implemented in commit `feat(ai): human-in-the-loop-permission-advisor`.

---

## 4. Reusable Prompts & System Directives

To maintain security hygiene, we enforced the following system prompt context across our workflow:
```markdown
[SECURITY CONSTITUTION]
1. Never propose client-side authorization as a defense. The server must validate every request.
2. In access control, default deny (403) must apply to all ungranted resources.
3. Every state change and refused attempt must be immutable and audit-logged.
4. Revocation must take effect with zero TTL delay.
5. AI must never autonomously elevate access rights without explicit human approval.
```
