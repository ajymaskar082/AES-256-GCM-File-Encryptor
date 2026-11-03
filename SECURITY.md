# Security Policy

## Cryptographic Security

- AES-256-GCM is used for file encryption.
- PBKDF2WithHmacSHA256 derives keys from passwords.
- Random salt and IV are generated for each encryption.
- GCM authentication detects corrupted data.
- Passwords and secret keys must not be stored in the repository.  
