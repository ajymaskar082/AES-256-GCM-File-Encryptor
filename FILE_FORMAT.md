# Encrypted File Format

The encrypted file contains the following sections:

| Field | Size | Description |
|---|---:|---|
| MAGIC | 4 bytes | File format identifier (AGCM) |
| Salt | 16 bytes | Random PBKDF2 salt |
| IV | 12 bytes | Random GCM initialization vector |
| Encrypted Data | Variable | Ciphertext and authentication tag |

## Encryption Parameters

- Algorithm: AES-256-GCM
- Key derivation: PBKDF2WithHmacSHA256
- Iterations: 120000
- Authentication tag: 128 bits
- Processing buffer: 64 KB
