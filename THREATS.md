# THREATS.md — TrustVault Threat Model & Defense Matrix

**Author:** Snovasys Fresher Hiring Challenge 2026 Candidate  
**System:** TrustVault — Zero-Trust Document Vault with Cryptographic Audit Trail  
**Target Standard:** "A document is reachable only by someone who was granted it... You can prove who reached it... Taking access away works immediately."

---

## 1. Executive Threat Architecture

TrustVault operates under an explicit **Zero-Trust DAC/RBAC Model**. We operate under the premise that:
1. The client browser environment is untrusted and can be forged (via `curl`, DevTools, or Postman).
2. The network may contain malicious eavesdroppers or rogue users attempting horizontal privilege escalation.
3. Insiders (including compromised administrators) may attempt covert exfiltration and log repudiation.

---

## 2. Threat Catalog & Defense Matrix

### Threat 1: Insecure Direct Object Reference (IDOR / BOLA)
- **Attack Vector:** An authenticated viewer (`alex.rivera@temp.net`) receives a document ID or scans sequential IDs (e.g. `doc-hr-101`, `doc-fin-102`) and invokes `GET /api/documents/doc-hr-101` directly.
- **Severity:** Critical (35/35 Mark Evaluation Criteria).
- **Defense Implemented:** Server-side mandatory authorization barrier via `evaluateAccess(user, doc, 'READ')` in `src/services/securityEngine.ts`. The server ignores client state and validates whether the calling identity holds an active grant in `doc.grants` or is the verified owner.
- **Proof & Non-Repudiation:** Direct IDOR calls return `HTTP 403 Forbidden` and trigger an immediate audit record with status `DENIED_403` committed to the SHA-256 hash chain.
- **Automated Test:** `SEC-TEST-01` in `test-security.ts`.

---

### Threat 2: Stale Permissions & Delayed Revocation Window (JWT / Caching Traps)
- **Attack Vector:** An owner revokes access for an employee or contractor, but the target continues to download files using an unexpired signed URL, bearer token, or cached browser handle.
- **Severity:** Critical (Standard Three Non-Negotiable).
- **Defense Implemented:** Zero-TTL authorization architecture. No time-decay tokens are used for file downloads. Every fetch, view, and stream checks live server state. Upon revocation:
  1. The target user's grant status is mutated to `REVOKED`.
  2. The document's `permissionVersion` is incremented.
  3. The target user's session version is incremented.
  Any streaming handle or subsequent request referencing older versions or revoked grants fails immediately with `HTTP 403`.
- **Automated Test:** `SEC-TEST-02` in `test-security.ts`.

---

### Threat 3: Audit Trail Tampering & Repudiation
- **Attack Vector:** An attacker or rogue database administrator alters database log rows to erase evidence of unauthorized access or frame another user.
- **Severity:** High (Standard Two Non-Negotiable).
- **Defense Implemented:** SHA-256 Merkle-style hash chaining. Each audit log entry $E_n$ commits the hash of $E_{n-1}$ into its signature:
  $$\text{Hash}_n = \text{SHA-256}(n \parallel \text{timestamp} \parallel \text{actorId} \parallel \text{action} \parallel \text{resourceId} \parallel \text{status} \parallel \text{reason} \parallel \text{Hash}_{n-1})$$
  Modifying even a single character in entry $k$ alters $\text{Hash}_k$, which breaks the link $\text{Hash}_{k+1}.\text{previousHash}$, causing mathematical verification to fail immediately.
- **Verification Engine:** `verifyAuditChainIntegrity()` inspects every link from Genesis to Head.
- **Automated Test:** `SEC-TEST-03` in `test-security.ts`.

---

### Threat 4: MIME Type Spoofing & Disguised Executable Uploads
- **Attack Vector:** An attacker renames a Windows PE executable (`backdoor.exe`) or shell script to `bonus_schedule.pdf` to execute client-side code on victim devices.
- **Severity:** High.
- **Defense Implemented:** Four-stage upload validation in `validateAndUploadDocument()`:
  1. Strict MIME whitelist (`application/pdf`, `.docx`, `.txt`, `.md`, `.json`).
  2. Extension vs MIME cross-check (rejecting `.exe` claiming to be `application/pdf`).
  3. Magic byte sniffing: Rejection of payloads starting with Windows PE signature `MZ` or Linux ELF `\x7fELF`.
  4. Hard payload size ceiling of 15MB.
- **Automated Test:** `SEC-TEST-05` in `test-security.ts`.

---

### Threat 5: Directory Path Traversal Exploits
- **Attack Vector:** Attacker provides filenames like `../../../../etc/shadow` or `%2e%2e%2f` to overwrite or leak arbitrary system files.
- **Severity:** High.
- **Defense Implemented:** File name sanitization regex rejecting `..`, `/`, `\`, null bytes, and path separators. File system keys are isolated and generated via cryptographically random UUIDs.
- **Automated Test:** `SEC-TEST-04` in `test-security.ts`.

---

### Threat 6: Horizontal Privilege Escalation (Read-to-Write Escalation)
- **Attack Vector:** A user with legitimate `READ` access on a contract issues a `PUT /api/documents/:id` request with altered payment terms or indemnities.
- **Severity:** High.
- **Defense Implemented:** Distinct permission levels (`READ` vs `EDIT`). `evaluateAccess(..., 'EDIT')` explicitly checks that `grant.accessLevel === 'EDIT'`. Read-only holders are rejected with `HTTP 403`.
- **Automated Test:** `SEC-TEST-06` in `test-security.ts`.

---

### Threat 7: Autonomous AI Permission Escalation
- **Attack Vector:** An AI integration automatically expands access permissions based on LLM output without human governance.
- **Severity:** Medium / High.
- **Defense Implemented:** Architectural isolation. AI is restricted to recommendation generation (`generateAIPermissionSuggestions`). The machine has no database write access. A human document owner must explicitly confirm each grant. Both the AI suggestion and the owner's confirmation are logged to the audit ledger.

---

## 3. Knowingly Accepted Risks & Rationale

Honesty in threat modeling is explicitly marked. The following residual risks are acknowledged:

1. **Analog / Screen Capture Side-Channel (The "Phone Camera" Attack):**
   - *Threat:* An authorized user with legitimate access photographs their monitor or uses an external HDMI capture card.
   - *Why Accepted:* Operating systems and web browsers cannot prevent physical cameras from recording display photons.
   - *Compensating Control:* Dynamic forensic watermarking embedded directly into the decrypted document stream with the viewer's email, sequence number, and timestamp, making leaked photos traceable back to the leaker.

2. **Compromised User Device / Keystroke Logging:**
   - *Threat:* An attacker with root access on the user's workstation logs session credentials.
   - *Why Accepted:* Host OS compromises fall under endpoint security rather than document vault authorization.
   - *Compensating Control:* Mandatory multi-factor authentication (MFA) and granular audit logs with client IP recording.

3. **Storage At Rest Key Escrow (In-Memory / Single Node Scope):**
   - *Threat:* Physical disk theft in unencrypted environments.
   - *Why Accepted:* Cloud environments typically enforce volume encryption (e.g., GCP Cloud KMS / AWS KMS) at the infrastructure layer.
