<<<<<<< HEAD
# TrustVault — Secure Document Sharing with a Real Audit Trail

> **Snovasys Fresher Hiring Challenge 2026 Submission**  
> *"A document platform where the wrong person can never read the file, and you can prove who read it."*

---

## 1. Quick Start & Test Execution

### Installation & Local Run
```bash
# 1. Install dependencies
npm install

# 2. Run automated security test suite (Requirement #10)
npx tsx test-security.ts

# 3. Launch live web application & attack simulator
npm run dev
```

The application runs on `http://localhost:3000`.

---

## 2. Seed Credentials & Role Directory

Pre-configured accounts for testing each role:

| Name | Role | Email | Capabilities & Initial State |
|---|---|---|---|
| **Sarah Jenkins** | `admin` | `admin@trustvault.internal` | Chief Compliance Officer. Can inspect the entire cryptographic audit trail, verify SHA-256 chain integrity, toggle document lockdowns, and review refused access attempts. |
| **David Vance** | `owner` | `david.vance@company.com` | VP of HR & Executive Comp. Owner of *"Executive Salary & Bonus Letters FY2026"* and *"Q3 Financial Audit"*. Has sole authority to grant/revoke access. |
| **Elena Rostova** | `owner` | `elena.rostova@legal.org` | General Counsel. Owner of *"Master Services Agreement"* and *"Neural IP Patent Claims"*. Granted EDIT to Marcus and READ to Chloe. |
| **Marcus Chen** | `viewer` | `marcus.chen@engineering.com` | Senior Engineer. Has active `EDIT` grant on *"Neural IP Patent Claims"*. Has **ZERO** access to David's salary letters. |
| **Chloe Patel** | `viewer` | `chloe.patel@external-contractor.io` | External Legal Advisor. Has active `READ` grant on *"Master Services Agreement"*. Cannot edit or view other files. |
| **Alex Rivera** | `viewer` | `alex.rivera@temp.net` | Unassigned Employee. Holds **ZERO** grants. Used to test unprivileged access, IDOR attacks, and 403 audit logging. |

*Note: In the live web UI, use the top-right persona switcher to switch between these users with one click.*

---

## 3. The Three Non-Negotiable Standards: How TrustVault Meets Them

### Standard One: Server Decides Every Time (Zero-Trust)
- **The Guarantee:** Access is never gated only on the client. 
- **Code Enforcement:** In `src/services/securityEngine.ts`, `evaluateAccess(user, doc, action)` is executed on every single API route (`GET`, `PUT`, `DELETE`, `DOWNLOAD`).
- **Proof:** Attempting to fetch `doc-hr-101` as Marcus or Alex returns `HTTP 403 Forbidden` and creates an immutable `DENIED_403` audit block.

### Standard Two: Cryptographic, Tamper-Evident Audit Trail
- **The Guarantee:** You can prove who reached a document and who was refused. The record cannot be quietly altered.
- **Code Enforcement:** In `src/services/cryptoLedger.ts`, every event is cryptographically hashed with SHA-256 and chained to the previous block hash ($E_n.\text{hash} = \text{SHA-256}(\dots \parallel E_{n-1}.\text{hash})$).
- **Proof:** Click **"Simulate Tampering"** in the web UI or run `verifyLedgerIntegrity()`. Modifying even one letter in a historical entry breaks the hash chain and pinpoints the exact sequence number.

### Standard Three: Instant Revocation (Zero-TTL)
- **The Guarantee:** Whatever was issued stops working immediately.
- **Code Enforcement:** TrustVault does not rely on cached JWTs with expirations. Revocation mutates the grant to `REVOKED`, increments `doc.permissionVersion`, and increments the user's `sessionVersion`. Any subsequent download request arriving even 1 millisecond later evaluates to `HTTP 403`.

---

## 4. Live Attack Console (Requirement #10)

TrustVault includes an integrated **Judge Attack Console** in the web UI (`Tab: Judge Attack Suite`) and CLI (`test-security.ts`).

### Automated Test Matrix:
1. **SEC-TEST-01 (IDOR Prevention):** Alex Rivera attempts direct `GET /api/documents/doc-hr-101`. Server rejects with `HTTP 403` and logs refusal.
2. **SEC-TEST-02 (Instant Revocation):** Temporary grant assigned to Alex $\rightarrow$ Alex can read $\rightarrow$ Owner revokes grant $\rightarrow$ Alex's immediate subsequent request is blocked with `HTTP 403`.
3. **SEC-TEST-03 (SHA-256 Ledger Integrity):** Verifies all block links and signatures across the entire ledger from Genesis.
4. **SEC-TEST-04 (Path Traversal Rejection):** Upload with `../../../../etc/shadow` filename is rejected with `HTTP 400`.
5. **SEC-TEST-05 (Magic Byte Sniffing):** Upload disguised as `.pdf` with Windows PE header (`MZ`) is rejected with `HTTP 400`.
6. **SEC-TEST-06 (Privilege Escalation Block):** Chloe Patel (READ grant) attempts `PUT` to alter contract terms; rejected with `HTTP 403`.
7. **SEC-TEST-07 (Refusal Proof):** Confirms that all 403 blocked attempts are committed into the audit chain.

---

## 5. Interview Walkthrough Defense

> *"Shortlisted candidates walk through their own code and make a change we pick, live. Expect to be asked where the authorisation decision is made when someone downloads a file, and what would happen if that line were removed."*

### 1. Where is the authorization decision made when downloading a file?
It is made in `src/services/securityEngine.ts` inside `downloadDocument()`:
```typescript
const check = this.evaluateAccess(user, doc, 'DOWNLOAD');
if (!check.allowed) {
  this.logAuditEvent({
    actor: user,
    action: 'ACCESS_DENIED_UNAUTHORIZED',
    status: 'DENIED_403',
    ...
  });
  return { success: false, error: check.reason, httpStatus: check.httpStatus };
}
```

### 2. What would happen if that check were removed?
If that line is removed, the automated test suite will **immediately fail**:
- `SEC-TEST-01` (IDOR attack test) will fail because unprivileged user Alex Rivera will receive HTTP 200 instead of HTTP 403.
- `SEC-TEST-02` (Revocation test) will fail because a revoked user will still receive file content.
- The tests are tightly bound to the authorization logic.

---

## 6. What Was Built vs. What Was Deliberately Omitted

### What We Built:
1. Complete zero-trust DAC/RBAC authorization engine.
2. SHA-256 cryptographic hash-chain ledger with live tamper verification.
3. Multi-layer upload validation (magic bytes, MIME check, path traversal regex).
4. Dynamic forensic watermarking on document streams.
5. AI Access Policy Advisor (strictly advisory, human confirms, full audit log).
6. 100% test-backed security test suite.

### What We Deliberately Did Not Build (and Why):
1. **Self-Contained Client JWTs for File Access:** We chose zero-TTL state checks because time-decay tokens create a vulnerable exposure window during revocation (Standard Three).
2. **Autonomous AI Permission Granting:** We deliberately refused to allow an AI model to modify database grants directly. Machine models can hallucinate or be tricked by prompt injection; keeping a human in the loop is essential for document security.
3. **Complex Nested Folder Inheritance:** Hierarchical folder permissions often lead to unintended permission creep ("Someone is given access to a folder so they can see one file, and they can now see forty"). Direct, explicit per-document grants eliminate this failure mode entirely.

---

## 7. Submission Artifacts
- `THREATS.md`: Exhaustive STRIDE threat model and accepted risks.
- `PROMPTS.md`: 5 dated entries detailing AI authorization mistakes and manual corrections.
- `API.md`: Detailed endpoint authorization matrix and failure behaviors.
- `test-security.ts`: Runnable CLI automated penetration test suite.
=======
# TrustVault---Secure-Document-Sharing-Tamper-Evident-Audit
>>>>>>> 0779e0e65805db8bb4324e831c195a6950b6dcd8
