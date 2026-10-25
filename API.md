# API.md — TrustVault Endpoint & Authorization Specifications

All endpoints require authentication via Bearer session context or cryptographic identity.  
**Default Security Posture:** Explicit Deny (`HTTP 403 Forbidden`).

---

## Endpoint Matrix

| Method | Endpoint | Allowed Roles | Description | Failure Statuses |
|---|---|---|---|---|
| `GET` | `/api/documents` | All authenticated (`admin`, `owner`, `viewer`) | List accessible documents. Owners see owned files; Viewers see granted files; Admins see governance catalog. | `401 Unauthorized` |
| `GET` | `/api/documents/:id` | Document Owner, Admin, or Viewer with `ACTIVE` grant | Retrieve document metadata and decrypted content stream. | `401`, `403 Forbidden` (ungranted IDOR attempt), `404` |
| `GET` | `/api/documents/:id/download` | Document Owner, Admin, or Viewer with `ACTIVE` grant | Download decrypted document stream with dynamic viewer watermark. | `401`, `403 Forbidden`, `404` |
| `POST` | `/api/documents` | `owner`, `admin` (Viewers blocked) | Upload and ingest validated document into vault. | `400 Bad Request` (traversal / magic bytes), `403`, `413 Too Large`, `415 Unsupported Media` |
| `PUT` | `/api/documents/:id` | Document Owner or Viewer with `EDIT` grant | Update document content and recompute cryptographic checksum. | `401`, `403 Forbidden` (Read-only grant), `423 Locked` |
| `DELETE` | `/api/documents/:id` | Document Owner, Admin (Viewers blocked) | Purge document from vault. Logged to immutable audit trail. | `401`, `403 Forbidden`, `404` |
| `POST` | `/api/documents/:id/lock` | Document Owner, Admin | Toggle administrative lockdown. | `401`, `403 Forbidden`, `404` |
| `POST` | `/api/documents/:id/permissions` | Document Owner (Admin compliance override) | Grant `READ` or `EDIT` access to named identity. Bumps `permissionVersion`. | `401`, `403 Forbidden`, `404` |
| `POST` | `/api/documents/:id/permissions/revoke` | Document Owner (Admin compliance override) | Immediately revoke access. Bumps `permissionVersion`. | `401`, `403 Forbidden`, `404` |
| `GET` | `/api/audit-logs` | `admin` (all), `owner` (owned documents) | Fetch tamper-evident audit ledger entries. | `401`, `403 Forbidden` (Viewers blocked) |
| `GET` | `/api/audit-logs/verify` | `admin`, Auditor | Recalculate and verify SHA-256 hash chain from Genesis. | `401`, `403 Forbidden` |
| `POST` | `/api/security-test-suite` | All / Evaluator | Executes the 7 automated security penetration tests. | `200 OK` |

---

## Detailed Endpoint Specifications

### 1. Retrieve Document
```http
GET /api/documents/:id HTTP/1.1
Authorization: Bearer <session-token>
```
- **Authorization Rule:**
  - If `user.id === doc.ownerId` $\rightarrow$ `200 OK`.
  - If `user.role === 'admin'` $\rightarrow$ `200 OK` (compliance audit access).
  - If `doc.grants.some(g => g.userId === user.id && g.status === 'ACTIVE')` $\rightarrow$ `200 OK`.
  - Otherwise $\rightarrow$ `403 Forbidden`.
- **Security Audit Effect on 403:**
  The server creates an immutable audit entry:
  - `action`: `ACCESS_DENIED_UNAUTHORIZED`
  - `status`: `DENIED_403`
  - `reason`: `ACCESS REFUSED: User <email> attempted read without grant.`
  - Hashed and linked into the SHA-256 audit ledger.

---

### 2. Download Decrypted Document Stream
```http
GET /api/documents/:id/download HTTP/1.1
Authorization: Bearer <session-token>
```
- **Response Headers:**
  ```http
  Content-Type: application/pdf
  Content-Disposition: attachment; filename="Executive_Comp_FY2026.pdf"
  X-TrustVault-Audit-Seq: #12
  X-TrustVault-Checksum: e3b0c44298fc1c14...
  ```
- **Watermark Specification:** Decrypted payload stream includes a tamper-evident trailer indicating recipient identity, IP address, and timestamp.

---

### 3. Grant Permission to Named User
```http
POST /api/documents/:id/permissions HTTP/1.1
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "targetUserId": "usr-viewer-01",
  "accessLevel": "EDIT",
  "notes": "Co-authoring patent claims"
}
```
- **Authorization Rule:** Only the document owner or system administrator can grant access.
- **Side Effects:**
  1. Creates active permission grant with timestamp.
  2. Bumps `doc.permissionVersion`.
  3. Records `PERMISSION_GRANTED` block in the cryptographic audit ledger.

---

### 4. Instant Revocation
```http
POST /api/documents/:id/permissions/revoke HTTP/1.1
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "targetUserId": "usr-viewer-01"
}
```
- **Authorization Rule:** Document Owner or Admin.
- **Standard Three Guarantees:**
  1. Grant status mutated to `REVOKED`.
  2. Document `permissionVersion` incremented.
  3. Target user's `sessionVersion` incremented.
  4. Subsequent requests from target fail with `403 Forbidden` immediately.
  5. Records `PERMISSION_REVOKED` block in the cryptographic audit ledger.

---

### 5. Document Ingestion & Upload
```http
POST /api/documents HTTP/1.1
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "title": "Bilateral NDA Executed",
  "description": "Standard mutual confidentiality",
  "category": "Legal & Contracts",
  "sensitivityLevel": "Confidential",
  "fileName": "NDA_Signed.pdf",
  "fileType": "application/pdf",
  "content": "<base64 or text payload>"
}
```
- **Validation Gates:**
  - Role: `owner` or `admin`. (Viewers receive `403`).
  - Size: Payload $\le 15\text{MB}$. (Otherwise `413 Payload Too Large`).
  - Path: Filename matches `^[\w\-.]+$`. Rejects `..`, `/`, `\`, null bytes. (Otherwise `400 Bad Request`).
  - Magic Bytes: Payload cannot start with `MZ` (Windows PE) or `\x7fELF` (Linux executable). (Otherwise `400 Bad Request`).
  - MIME: Only allowed types (`application/pdf`, `.docx`, `.txt`, `.md`, `.json`). (Otherwise `415 Unsupported Media Type`).
