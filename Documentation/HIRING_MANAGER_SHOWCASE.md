# Hiring manager showcase

## What to review in five minutes

1. Open **Security Workflow** in the authenticated Django navigation. The page presents the exact six-stage transformation used by the project, not merely an architecture claim.
2. Review `crud/services/hybrid_security.py`. The service is separated from the view layer, so it is testable and can be used by an upload endpoint or background worker.
3. Run the hybrid tests. They show a real plaintext-to-stego-PNG-to-plaintext round trip and cover wrong-key and capacity failures.
4. Review the Python and Java MySQL connection examples for environment-only credentials, TLS defaults, connection timeouts, and deterministic cleanup.

## Engineering decisions demonstrated

| Concern | Implementation | Why it matters |
| --- | --- | --- |
| Confidentiality | AES-256-GCM with a 96-bit random nonce | Modern authenticated encryption protects the compressed file. |
| Key establishment | Ephemeral P-256 ECDH + HKDF-SHA-256 | A distinct symmetric key is derived per protected file. |
| Integrity | AES-GCM authentication plus SHA-256 verification | Ciphertext tampering and incorrect recovered content are rejected. |
| Concealment | RGB LSB embedding in a lossless PNG | The encrypted payload is not stored as a plainly visible file blob. |
| Reliability | Versioned frame, length check, capacity check, typed errors | Invalid or truncated payloads fail safely. |
| Operations | Environment-configured Python/Java MySQL clients | Credentials stay out of the repository and resources are closed. |

## Demonstration script

> “The upload integration calls `encrypt_and_embed` with the user’s bytes, a PNG cover image, and the recipient public key. The service hashes and LZW-compresses the file; ephemeral ECC derives an AES key; AES-GCM encrypts it; and LSBs conceal the framed payload. On retrieval, only the private-key holder can derive the decryption key. AES-GCM and SHA-256 must both pass before plaintext is returned.”

## Scope and next production step

The cryptographic service is complete and UI-visible. The next deployment step is to connect the existing file-upload form to an authenticated key-management service and object storage, rather than storing recipient private keys in the web application.
