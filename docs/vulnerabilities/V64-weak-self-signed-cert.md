# V64: Self-Signed Certificate Weak Key

**Severity:** LOW
**Category:** Cryptography
**Auto-Fix:** No (requires code change)

## Description

Self-signed certificates are generated with RSA 2048-bit keys. While currently adequate, NIST recommends 3072-bit for security past 2030.

## Affected Code

- `src/infra/tls/gateway.ts:49`
- Command: `-newkey rsa:2048`

## Risk

- Future cryptographic weakness
- 10-year validity exceeds key security lifetime
- Not compliant with modern standards

## Detection

```bash
# Check certificate key size
openssl x509 -in ~/.clawdbot/tls/gateway.crt -text -noout | grep "Public-Key"
```

## Remediation

1. Use stronger key size:
```typescript
// Change from rsa:2048 to rsa:4096
const cmd = `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem ...`;
```

2. Or switch to ECDSA:
```typescript
const cmd = `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 ...`;
```

3. Reduce validity period:
```typescript
// Change from 3650 days (10 years) to 365 days (1 year)
const cmd = `openssl req -x509 ... -days 365 ...`;
```

4. Regenerate existing certificates:
```bash
# Backup old cert
mv ~/.clawdbot/tls/gateway.crt ~/.clawdbot/tls/gateway.crt.bak

# Generate new with stronger key
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
  -keyout ~/.clawdbot/tls/gateway.key \
  -out ~/.clawdbot/tls/gateway.crt \
  -subj "/CN=moltbot-gateway" \
  -nodes
```

## References

- [NIST Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
