# Database connection examples

These production-oriented examples support the project's MySQL data store without
embedding credentials in source code. Both implementations use the same environment
variables shown in [`.env.example`](.env.example), apply a 10-second connection timeout,
require TLS by default, and close resources deterministically.

## Python

Install dependencies and run the unit tests:

```bash
pip install -r requirements.txt
PYTHONPATH=database/python python -m unittest discover -s database/python/tests -v
```

After exporting the database variables, run a health check:

```bash
python database/python/mysql_connection.py
```

`MySQLDatabase.session()` is a context manager for application queries; it closes the
connection even when an exception occurs.

## Java

The Java example uses the MySQL JDBC driver at runtime. Download it through your build
tool (Maven coordinate: `com.mysql:mysql-connector-j`) and include it on the runtime
classpath. Compile the source with:

```bash
javac database/java/DatabaseConnection.java
```

Then run `DatabaseConnection` with the JDBC driver on the classpath and the same `DB_*`
environment variables exported.

## Hybrid-security implementation

The project logic now lives in [`crud/services/hybrid_security.py`](../crud/services/hybrid_security.py), rather than only in the project description. It implements the full reversible flow:

1. Calculate a SHA-256 hash of the original bytes.
2. Compress the bytes using the included deterministic 16-bit LZW implementation.
3. Generate an ephemeral P-256 ECC key and use ECDH + HKDF-SHA-256 to derive a per-file AES-256 key.
4. Encrypt the compressed content with AES-GCM; the original hash is authenticated additional data.
5. Put the version, hash, ephemeral public key, nonce, and ciphertext in a framed payload, then embed it into RGB least-significant bits of a lossless PNG.
6. On extraction, derive the same key with the recipient private key, authenticate/decrypt, decompress, and compare SHA-256 before returning any plaintext.

The unit suite exercises a full round trip, LZW round trip, insufficient cover-image capacity, and decryption with the wrong recipient key:

```bash
python -m unittest discover -s tests -v
```

## Hiring-manager notes

The examples demonstrate deployment-ready fundamentals: configuration separation,
least exposure of secrets, encrypted transport by default, bounded connection attempts,
and automatic cleanup of database resources. The `SELECT 1` health checks are intentionally
non-destructive, making them suitable for service readiness checks.
